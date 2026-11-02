using System.Net;
using System.Net.Sockets;

namespace Router;

// The IPv6 side: one DHCPv6 client asking the WAN for a prefix, and the Router Advertisements that hand
// that prefix to the LAN. The two halves share one thread because they share state - the advertisement is
// built from the delegation, and a prefix that changes has to be withdrawn before the new one is offered -
// and one thread is what keeps them from needing a lock between them.
//
// The route is not translated: with a delegated prefix the LAN addresses are real addresses, so the
// host's own forwarding carries a client's packet and this class only makes the WAN give it one and the
// LAN's hosts use it.
public sealed class V6Router
{
    private static readonly IPAddress AllRelayAgents = IPAddress.Parse(Dhcp6.AllRelayAgentsAndServers);
    private static readonly IPAddress AllNodes = IPAddress.Parse("ff02::1");
    private static readonly IPAddress AllRouters = IPAddress.Parse("ff02::2");

    // RFC 4861 §6.2.1's default MaxRtrAdvInterval, used for both the interval draw and the lifetimes that
    // are quoted as a multiple of it.
    private static readonly TimeSpan RaInterval = TimeSpan.FromSeconds(600);

    // RFC 4861 §6.2.1 requires AdvDefaultLifetime to be zero or a value between MaxRtrAdvInterval and
    // 9000; three intervals is its default. RFC 8106 §5.1 asks for a resolver lifetime of at least three
    // intervals, so that a missed advertisement does not take the resolver away with it.
    private static readonly uint RouterLifetime = (uint)(3 * RaInterval.TotalSeconds);
    private static readonly uint DnsLifetime = (uint)(3 * RaInterval.TotalSeconds);

    // RFC 8781 §4.1: "By default, the value of the Scaled Lifetime field SHOULD be set to the lesser of
    // 3 x MaxRtrAdvInterval [RFC4861] divided by 8, or 8191." That is 225 in the field, and this side is
    // counted in seconds because §4.1 makes the receiver multiply by 8, so the figure here is 1800 s - far
    // inside the 65528 s the 13-bit field caps at. It is the same three intervals that §6.2.1 and RFC 8106
    // §5.1 set the two lifetimes above to, which is what §4.1's "does not expire before the default
    // router" requirement asks for.
    private static readonly uint Pref64Lifetime = (uint)(3 * RaInterval.TotalSeconds);

    // How long to wait for a freshly added address to leave Duplicate Address Detection before putting the
    // DNS listeners on it. RFC 4862 §5.1's defaults are DupAddrDetectTransmits (1) times RetransTimer
    // (1000 msec) plus a random delay of up to 1000 msec, so this covers the default and still returns
    // promptly when an address is refused for some other reason.
    private static readonly TimeSpan UsableAddressWait = TimeSpan.FromSeconds(4);

    // RFC 8415 §12: the IAID "MUST be consistent across restarts of the DHCP client", and "if the client
    // uses only one IAID, it can use a well-known value". This client has exactly one IA_PD on this
    // interface, so a constant is the value that stays stable.
    private const uint Iaid = 0x524F5636;

    private readonly string _lanName;
    private readonly int _lanIfIdx;
    private readonly IPAddress _lanLinkLocal;
    private readonly byte[] _lanMac;
    private readonly uint _mtu;
    private readonly UdpClient _dhcp;
    private readonly Socket _icmp;
    private readonly PdClient _pd;

    private RaSchedule? _ra;
    private DateTime? _answerAt;
    private IPAddress? _answerTo;
    private Dhcp6Prefix? _installed;
    private IPAddress? _installedAddress;
    private DateTime _preferredUntil;
    private DateTime _validUntil;
    private IReadOnlyList<byte[]> _dns = Array.Empty<byte[]>();
    // Whether the resolver is actually listening on the address below, which is what decides whether the
    // advertisement may name it.
    private bool _resolverListening;

    // Set once this run has a resolver of its own. The advertisement then names this host's own LAN
    // address as the recursive resolver rather than the delegation's, which is what puts every answer a
    // LAN client gets through the resolver that takes the ECH configuration out of it.
    public bool AnswersDnsItself { get; set; }

    // Set when this run's resolver synthesizes AAAA records. The advertisement then carries RFC 8781's
    // PREF64 option, which is the other half of the pairing RFC 6147 §5.2 asks for - "The same algorithm
    // to create an IPv6 address from an IPv4 address MUST be used by both a DNS64 ... and by an IPv6/IPv4
    // translator" - because a host that synthesizes for itself has to be given the prefix the answers it
    // is already receiving were built with.
    public Pref64Config? Pref64 { get; set; }

    // Raised on this thread with the address the delegation installed on the LAN interface, and with null
    // when it is taken back. A socket bound to an address no interface holds fails, so the resolver's
    // IPv6 listener is opened from here instead of at startup beside the IPv4 one. The handler reports
    // whether its UDP listener bound: naming an address nothing listens on is the failure this choice
    // exists to avoid, so a bind that failed puts the delegation's own resolver back in the option.
    public event Func<IPAddress?, bool>? ResolverAddressChanged;

    private V6Router(string lanName, int lanIfIdx, IPAddress lanLinkLocal, byte[] lanMac,
        uint mtu, UdpClient dhcp, Socket icmp, PdClient pd)
    {
        _lanName = lanName;
        _lanIfIdx = lanIfIdx;
        _lanLinkLocal = lanLinkLocal;
        _lanMac = lanMac;
        _mtu = mtu;
        _dhcp = dhcp;
        _icmp = icmp;
        _pd = pd;
    }

    public static V6Router? Open(InterfaceInfo wan, InterfaceInfo lan)
    {
        if (Host.LinkLocal(wan.IfIdx) is not { } wanFound)
        {
            Console.WriteLine($"[Router] IPv6 off: {wan.Name} has no usable link-local address to ask for a prefix from.");
            return null;
        }
        // The shell prints the zone as an interface index; WithScope puts the one we queried with back on
        // after the parse dropped it.
        var wanLink = WithScope(wanFound.Address, wan.IfIdx);
        Console.WriteLine($"[Router] IPv6 WAN link-local on {wan.Name}: {wanLink} ({wanFound.State})");
        var wanMac = Host.MacAddress(wan.Name);
        if (wanMac is null)
        {
            Console.WriteLine($"[Router] IPv6 off: {wan.Name} reports no hardware address, so no DUID-LL can name this client.");
            return null;
        }
        if (Host.LinkLocal(lan.IfIdx) is not { } lanFound)
        {
            Console.WriteLine($"[Router] IPv6 off: {lan.Name} has no link-local address, which is the source a");
            Console.WriteLine("[Router]   Router Advertisement must carry (RFC 4861 §4.2).");
            return null;
        }
        var lanLink = WithScope(lanFound.Address, lan.IfIdx);
        Console.WriteLine($"[Router] IPv6 LAN link-local on {lan.Name}: {lanLink} ({lanFound.State})");
        // A Deprecated link-local still sends, and the RA names it as the source, so the checksum matches;
        // the state is reported because it usually means the interface has not finished coming up.
        if (!lanFound.State.Equals("Preferred", StringComparison.OrdinalIgnoreCase))
            Console.WriteLine($"[Router]   it is {lanFound.State}, not Preferred: an advertisement names it anyway");
        var lanMac = Host.MacAddress(lan.Name);
        if (lanMac is null)
        {
            Console.WriteLine($"[Router] IPv6 off: {lan.Name} reports no hardware address for the Source Link-Layer option.");
            return null;
        }

        // A zero MTU means there is nothing to tell the LAN, and the builder then omits the option rather
        // than advertising a link that cannot carry the IPv6 minimum.
        var mtu = Host.QueryMtu(wan.IfIdx) ?? 0;

        UdpClient? dhcp = null;
        Socket? icmp = null;
        try
        {
            dhcp = new UdpClient(AddressFamily.InterNetworkV6);
            dhcp.Client.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, true);
            dhcp.Client.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastLoopback, false);
            // RFC 8415 §7.2: "Clients listen for DHCP messages on UDP port 546", on the link-local address
            // of the interface the server is reached through. RFC 8415 §7.1 names the group a Solicit is
            // sent to, and joining it is what lets an Advertise addressed there be delivered to this socket.
            dhcp.Client.Bind(new IPEndPoint(wanLink, Dhcp6.ClientPort));
            dhcp.Client.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.AddMembership,
                new IPv6MulticastOption(AllRelayAgents, wan.IfIdx));
            // ff02::1:2 is link-local multicast and the address carries no zone of its own, so the
            // interface a Solicit leaves by is named here instead of being left to address resolution.
            dhcp.Client.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastInterface,
                wan.IfIdx);

            icmp = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.IcmpV6);
            // RFC 4861 §6.1.2: the IP hop limit of a Router Advertisement MUST be 255, and unicast answers
            // to a solicitation are held to the same 255. The names below are ws2ipdef.h's
            // IPV6_UNICAST_HOPS (4), IPV6_MULTICAST_HOPS (10) and IPV6_MULTICAST_IF (9), which are the
            // values .NET's IpTimeToLive, MulticastTimeToLive and MulticastInterface carry.
            icmp.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastLoopback, false);
            icmp.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IpTimeToLive, (int)Ra6.HopLimit);
            icmp.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastTimeToLive, (int)Ra6.HopLimit);
            icmp.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastInterface, lan.IfIdx);
            // A solicitation is sent to the all-routers group; without joining it this host is not a
            // recipient, and a host that just plugged in waits for the next periodic advertisement.
            icmp.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.AddMembership,
                new IPv6MulticastOption(AllRouters, lan.IfIdx));
            icmp.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));
        }
        catch (Exception ex) when (ex is SocketException or ArgumentException)
        {
            Console.WriteLine($"[Router] IPv6 off: {ex.GetType().Name}: {ex.Message}");
            // The only well-known port asked for above is RFC 8415 §7.2's client port, and the message that
            // comes back does not say who already has it, so the query that does is named here.
            if (ex is SocketException { SocketErrorCode: SocketError.AddressAlreadyInUse })
                Console.WriteLine("[Router]   holders of that port: Get-NetUDPEndpoint -LocalPort 546");
            dhcp?.Dispose();
            icmp?.Dispose();
            return null;
        }

        // Windows' own advertiser on the LAN is reported rather than turned off: if it is enabled, the host
        // advertises the prefix this program installs too, with its own lifetimes and no resolver option, so
        // a live run's RAs stop being attributable to one sender. Measured 2026-10-31 on this host: disabled.
        var advertiser = Host.QueryRaAdvertiser(lan.IfIdx);
        Console.WriteLine($"[Router] IPv6 on {lan.Name}: Windows' own Router Advertisements are " +
                          $"{advertiser ?? "unreadable"}");

        var pd = new PdClient(Dhcp6.DuidLl(wanMac), Iaid, 60, Random.Shared.NextDouble);
        Console.WriteLine($"[Router] DHCPv6 PD from {wanLink} ({wan.Name}) as IAID {Iaid:x8}, " +
                          $"advertising on {lan.Name} when a prefix arrives");
        return new V6Router(lan.Name, lan.IfIdx, lanLink, lanMac, mtu, dhcp, icmp, pd);
    }

    // One thread for the whole run: receive, retransmit, advertise. The 50 ms tick is far below any
    // interval either side keeps, and it keeps shutdown to one loop check.
    public void Run(CancellationToken token)
    {
        var buffer = new byte[1500];
        _pd.Start(DateTime.UtcNow);
        try
        {
            while (!token.IsCancellationRequested)
            {
                var now = DateTime.UtcNow;
                DrainDhcp6(now);
                DrainSolicitations(now, buffer);
                foreach (var step in _pd.Poll(now)) Apply(step, now);
                Timer(now);
                Thread.Sleep(50);
            }
        }
        catch (Exception ex)
        {
            // Nobody awaits this task, so a fault would end the IPv6 side with no line at all.
            Console.WriteLine($"[Router] IPv6 side failed: {ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            Shutdown();
        }
    }

    private void DrainDhcp6(DateTime now)
    {
        int available;
        try
        {
            available = _dhcp.Available;
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
        {
            return;
        }
        while (available > 0)
        {
            IPEndPoint from = new(IPAddress.IPv6Any, 0);
            byte[] datagram;
            try
            {
                datagram = _dhcp.Receive(ref from);
            }
            catch (SocketException ex)
            {
                Console.WriteLine($"[Router] DHCPv6 receive failed: {ex.Message}");
                return;
            }
            foreach (var step in _pd.Receive(datagram, from.Address, now)) Apply(step, now);
            try
            {
                available = _dhcp.Available;
            }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
            {
                return;
            }
        }
    }

    private void DrainSolicitations(DateTime now, byte[] buffer)
    {
        while (true)
        {
            EndPoint from = new IPEndPoint(IPAddress.IPv6Any, 0);
            int length;
            try
            {
                if (_icmp.Available == 0) return;
                length = _icmp.ReceiveFrom(buffer, ref from);
            }
            catch (SocketException ex)
            {
                Console.WriteLine($"[Router] ICMPv6 receive failed: {ex.Message}");
                return;
            }

            var message = buffer.AsSpan(0, length);
            // A raw IPv6 socket is handed the ICMPv6 message with no IPv6 header in front of it, so the
            // first octet is the type. Every ICMPv6 message this host sees arrives here, so everything
            // that is not type 133 leaves without a line.
            if (message.Length == 0 || message[0] != Ra6.Solicitation) continue;
            if (!Ra6.TrySolicitation(message, out var why))
            {
                Console.WriteLine($"[Router] malformed Router Solicitation from {from}: {why}");
                continue;
            }
            if (_ra is null) continue;

            var source = ((IPEndPoint)from).Address;
            var unicast = !source.Equals(IPAddress.IPv6Any) && !source.IsIPv6Multicast;
            _answerAt = _ra.Solicit(now, !unicast);
            _answerTo = unicast ? WithScope(source, _lanIfIdx) : null;
            Console.WriteLine($"[Router] Router Solicitation from {source}: answering " +
                              $"{(unicast ? "it directly" : "to all nodes")}");
        }
    }

    private void Apply(PdStep step, DateTime now)
    {
        switch (step)
        {
            case PdTransmit transmit:
                // RFC 8415 §14: a client's messages go to All_DHCP_Relay_Agents_and_Servers, and the interface
                // they leave by is the socket's own IPV6_MULTICAST_IF rather than anything in the address.
                try
                {
                    _dhcp.Send(transmit.Datagram, transmit.Datagram.Length,
                        new IPEndPoint(AllRelayAgents, Dhcp6.ServerPort));
                    Console.WriteLine($"[Router] dhcp6 {transmit.Note} -> {AllRelayAgents}");
                }
                catch (SocketException ex)
                {
                    Console.WriteLine($"[Router] dhcp6 send to {AllRelayAgents} failed: {ex.Message}");
                }
                break;

            case PdDelegated delegated:
                Console.WriteLine($"[Router] dhcp6 {delegated.Note} {delegated.Prefix} " +
                                  $"preferred {delegated.Preferred.TotalHours:0.#}h valid {delegated.Valid.TotalHours:0.#}h " +
                                  $"from {delegated.Server}" +
                                  (delegated.Dns.Count == 0
                                      ? ""
                                      : $", resolver option {string.Join(',', delegated.Dns.Select(Format))}"));
                Install(delegated, now);
                break;

            case PdWithdrawn withdrawn:
                Console.WriteLine($"[Router] dhcp6 prefix withdrawn: {withdrawn.Why}");
                Withdraw(now);
                break;
        }
    }

    private void Install(PdDelegated delegated, DateTime now)
    {
        // Checked first, because a prefix this LAN cannot hold must not disturb the one it already advertises:
        // the lifetimes below belong to this Reply, and writing them while the old prefix stays installed
        // would tell the hosts a validity that belongs to a delegation nobody has.
        if (!delegated.Prefix.TryLanSubnet(out var subnet))
        {
            Console.WriteLine($"[Router] {delegated.Prefix} cannot be a LAN subnet, so it is not advertised.");
            return;
        }

        _preferredUntil = now + delegated.Preferred;
        _validUntil = now + delegated.Valid;
        // The option is optional in a Reply, so an answer that names no resolver keeps the one learned
        // earlier rather than taking the LAN's resolver away mid-delegation.
        if (delegated.Dns.Count > 0) _dns = delegated.Dns;

        if (_installed is { } previous && !previous.SameAs(subnet))
        {
            // The hosts have to be told the old prefix is gone before the address that owns it is taken
            // down, and before the new advertisement offers a second one (RFC 4862 §5.5.3(e)). Clearing the
            // record of it matters for the same reason: if the new address cannot be installed, this run must
            // not go on claiming to hold the prefix it just removed.
            WithdrawRouters(now);
            RemoveAddress();
            _installed = null;
            _ra = null;
        }

        if (_installed is null)
        {
            var address = InterfaceAddress(subnet);
            if (!Host.AddIpv6Address(address, subnet.Length, _lanIfIdx))
            {
                Console.WriteLine("[Router] the delegated prefix is not installed, so it is not advertised either.");
                return;
            }
            _installed = subnet;
            _installedAddress = address;
            _ra = new RaSchedule(now, Random.Shared.NextDouble, RaInterval);
            // Between the address going on the interface and the listeners being put on it: while Duplicate
            // Address Detection is still running the bind is refused, and the advertisement below would then
            // name the delegation's resolver instead of this one.
            var (state, waited) = Host.WaitUsableAddress(address, _lanIfIdx, UsableAddressWait);
            if (waited || !Host.IsUsable(state))
            {
                Console.WriteLine($"[Router] {address} on ifIdx {_lanIfIdx} reads {state ?? "absent"}" +
                                  (waited ? " after waiting for Duplicate Address Detection" : "") + ".");
            }
            // Before the line below, so what that line says about the resolver is what the listeners did.
            // No handler at all means this run answers no DNS, which is the same answer as a handler whose
            // bind failed.
            _resolverListening = AnswersDnsItself && ResolverAddressChanged?.Invoke(address) == true;
            Console.WriteLine($"[Router] LAN {address}/{subnet.Length} on {_lanName} (ifIdx {_lanIfIdx}); " +
                              $"advertising {subnet} with router lifetime {RouterLifetime}s, " +
                              (_mtu == 0 ? "no MTU option" : $"MTU {_mtu}") + ", " + ResolverText(address));
            return;
        }

        // The same prefix came back with fresh lifetimes. The next advertisement carries them, and a burst
        // now is what a host that has just woken up needs (RFC 4861 §6.2.4).
        _ra?.Announce(now);
    }

    private void Withdraw(DateTime now)
    {
        WithdrawRouters(now);
        RemoveAddress();
        _ra = null;
        _answerAt = null;
        _answerTo = null;
        _installed = null;
        _installedAddress = null;
        _dns = Array.Empty<byte[]>();
    }

    private void WithdrawRouters(DateTime now)
    {
        if (_installed is not { } prefix) return;
        // RFC 4861 §6.2.5 allows up to MAX_FINAL_RTR_ADVERTISEMENTS final advertisements with a router
        // lifetime of zero; the prefix inside them carries both lifetimes at zero (RFC 4862 §5.5.3(e)).
        var message = Ra6.Withdraw(Advertisement(prefix, 0, 0, 0, 0), _lanLinkLocal, AllNodes);
        for (var i = 0; i < RaSchedule.MaxFinalAdvertisements; i++) Send(message, null);
        Console.WriteLine($"[Router] advertised {prefix} with both lifetimes zero");
    }

    private void RemoveAddress()
    {
        if (_installedAddress is not { } address) return;
        Host.RemoveIpv6Address(address, _lanIfIdx);
        _installedAddress = null;
        // The listener bound to it has to go with it: a socket left bound to an address that is no longer
        // installed keeps nothing reachable and reports nothing.
        ResolverAddressChanged?.Invoke(null);
    }

    private void Timer(DateTime now)
    {
        if (_ra is not { } schedule) return;
        if (_answerAt is { } at && now >= at)
        {
            var multicast = _answerTo is null;
            Advertise(now, _answerTo);
            _answerAt = null;
            _answerTo = null;
            // §6.2.6: a multicast answer resets the interface's timer as if an unsolicited advertisement
            // had just been sent; a unicast one is not part of that timer's schedule.
            if (multicast) schedule.Sent(now);
        }
        if (schedule.Due(now))
        {
            Advertise(now, null);
            schedule.Sent(now);
        }
    }

    private void Advertise(DateTime now, IPAddress? unicastTo)
    {
        if (_installed is not { } prefix) return;
        var valid = Remaining(_validUntil, now);
        var preferred = Remaining(_preferredUntil, now);
        var advertisement = Advertisement(prefix, valid, preferred, DnsLifetime, RouterLifetime);
        var message = Ra6.Build(advertisement, _lanLinkLocal, unicastTo ?? AllNodes);
        // The line is the only view of an advertisement this program gets before a host answers it, so it
        // names what went where and with which lifetimes. The resolver half is named per advertisement and
        // not only at install, because whether this process listens on the LAN address can change between
        // the two, and which address the RDNSS option carries is the whole question a client's DNS answer
        // turns on.
        Console.WriteLine($"[Router] ra {prefix} preferred {preferred}s valid {valid}s " +
                          $"from {_lanLinkLocal} to {unicastTo ?? AllNodes}, {ResolverOptions(advertisement)}");
        Send(message, unicastTo);
    }

    // What the advertisement's RFC 8106 §5.1 and RFC 8781 §4 options carry, as the client will read them:
    // the addresses in the order they are written and the lifetime they share, or the fact that no option
    // went out at all.
    private static string ResolverOptions(RaAdvertisement advertisement) =>
        (advertisement.RecursiveDns.Count == 0
            ? "no RDNSS option"
            : $"rdnss {string.Join(',', advertisement.RecursiveDns.Select(Format))} " +
              $"lifetime {advertisement.DnsLifetime}s")
        + (advertisement.Pref64 is { } pref64
            ? $", pref64 {pref64.Prefix.Prefix}/{pref64.Prefix.PrefixLength} " +
              $"lifetime {pref64.LifetimeSeconds}s"
            : ", no PREF64 option");

    private RaAdvertisement Advertisement(Dhcp6Prefix prefix, uint valid, uint preferred, uint dnsLifetime,
        uint routerLifetime) => new()
    {
        LinkLayerAddress = _lanMac,
        Prefix = prefix,
        PreferredLifetime = preferred,
        ValidLifetime = valid,
        Mtu = _mtu,
        RouterLifetime = routerLifetime,
        RecursiveDns = RecursiveDns(_resolverListening ? _installedAddress : null, _dns),
        DnsLifetime = dnsLifetime,
        Pref64 = Pref64 is { } advertised ? new Pref64Advertisement(advertised, Pref64Lifetime) : null,
    };

    // The address the RDNSS option names (RFC 8106 §5.1). This process' own LAN address is what makes
    // every answer a LAN client gets pass through the resolver that takes the ECH configuration out of
    // it; the delegation's own resolver option is what goes out instead when this run answers nothing - or
    // could not bind the address - because an address with no listener behind it is worse than one this
    // program does not control.
    public static byte[][] RecursiveDns(IPAddress? own, IReadOnlyList<byte[]> delegated) =>
        own is null ? [.. delegated] : [own.GetAddressBytes()];

    private string ResolverText(IPAddress own)
    {
        var asked = _dns.Count == 0 ? "nothing" : string.Join(',', _dns.Select(Format));
        if (_resolverListening)
            return $"resolver {Format(own.GetAddressBytes())} (this process, listening on it; it asks {asked})";
        if (!AnswersDnsItself)
            return _dns.Count == 0
                ? "no resolver (the Reply named none)"
                : $"resolver {asked}";
        var named = _dns.Count == 0 ? "none" : asked;
        return $"resolver {named} (this process could not listen on {Format(own.GetAddressBytes())})";
    }

    private void Send(byte[] message, IPAddress? unicastTo)
    {
        var destination = unicastTo is null ? AllNodes : WithScope(unicastTo, _lanIfIdx);
        try
        {
            _icmp.SendTo(message, new IPEndPoint(destination, 0));
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
        {
            Console.WriteLine($"[Router] Router Advertisement to {destination} failed: {ex.Message}");
        }
    }

    private void Shutdown()
    {
        var now = DateTime.UtcNow;
        // RFC 8415 §18.2.7 orders the withdrawal before the Release datagram, and PdClient emits the two
        // steps in that order; Apply handles each where it lands.
        foreach (var step in _pd.Release(now)) Apply(step, now);
        // Nothing bound means nothing to withdraw, and an address left by a crashed run is not this run's
        // to keep: the LAN has no prefix behind it any more.
        Withdraw(now);
        _dhcp.Dispose();
        _icmp.Dispose();
        Console.WriteLine("[Router] IPv6 side stopped");
    }

    // The lifetime a host is told is what is left of the delegation, counted down as it goes: RFC 4861
    // §6.2.1 allows either a decrementing value or a fixed one, and only the decrementing one keeps the
    // host's own expiry in step with the server's.
    private static uint Remaining(DateTime until, DateTime now)
    {
        var seconds = (until - now).TotalSeconds;
        return seconds <= 0 ? 0 : (uint)Math.Min(uint.MaxValue, seconds);
    }

    // The address this router holds inside the delegated subnet: the network address with the last bit
    // set, i.e. ::1. The prefix length is what installs the on-link route for the whole /64.
    private static IPAddress InterfaceAddress(Dhcp6Prefix subnet)
    {
        var bytes = (byte[])subnet.Address.Clone();
        bytes[15] |= 1;
        return new IPAddress(bytes);
    }

    // A link-local destination is only routable with the interface it belongs to attached, and an address
    // that came off a receive endpoint may carry none.
    private static IPAddress WithScope(IPAddress address, int ifIdx) =>
        address.AddressFamily == AddressFamily.InterNetworkV6 && address.IsIPv6LinkLocal && address.ScopeId == 0
            ? new IPAddress(address.GetAddressBytes(), ifIdx)
            : address;

    private static string Format(byte[] address) => new IPAddress(address).ToString();
}
