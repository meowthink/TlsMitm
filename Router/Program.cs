using System.Buffers.Binary;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using Router;
using TlsMitm;
using static TlsMitm.WinDivertPInvoke;

// The same clock the proxy's log carries, so one run's two consoles can be lined up line by line.
Console.SetOut(new TimestampWriter(Console.Out));

// A minimal IPv4 router: the host's own forwarding does the routing and this adds the stateful NAT
// Windows does not, by rewriting the address and transport identifiers of the packets forwarding hands
// over. It shares nothing with TlsMitm at runtime, and the two sit on different capture points: this one
// is the forwarding path, the proxy's is this machine's own traffic, so a flow forwarded here is not a
// flow the proxy sees until something hands it over.
Console.WriteLine("[Router] Minimal IPv4 NAT router (WinDivert)");
Console.WriteLine("[Router] Usage: Router [--lan <ipv4>] [--wan <ipv4>] [--enable-forwarding] [--stop-ics] " +
                  "[--pool <ipv4>/<count>] [--lease <min>] [--udp-timeout <sec>] [--dns <ipv4>] " +
                  "[--scope <cidr>,<pool>/<count>,<router>[,<dns>]] [--no-dhcp] [--no-dns] [--no-v6] " +
                  "[--pref64 [<ipv6>/<len>]] [--nat64] [--allow-lan-in] [--trace [<count>]] [--stats <sec>]");

var lanArg = Host.OptionValue(args, "--lan");
var wanArg = Host.OptionValue(args, "--wan");
var enableForwarding = args.Contains("--enable-forwarding");
var stopIcs = args.Contains("--stop-ics");
var allowLanIn = args.Contains("--allow-lan-in");
var trace = args.Contains("--trace");
// 60 was arbitrary and unusable on a busy host: the sniff budget was spent on this machine's own
// traffic before a client could join. The count is the only way to aim it at a specific exchange.
var traceCount = int.TryParse(Host.OptionValue(args, "--trace"), out var parsedTrace) && parsedTrace > 0
    ? parsedTrace
    : 60;
var statsSeconds = int.TryParse(Host.OptionValue(args, "--stats"), out var parsedStats) && parsedStats > 0
    ? parsedStats
    : 30;
var poolArg = Host.OptionValue(args, "--pool");
var leaseMinutes = int.TryParse(Host.OptionValue(args, "--lease"), out var parsedLease) && parsedLease > 0
    ? parsedLease
    : 24 * 60;
var dnsArg = Host.OptionValue(args, "--dns");
var noDhcp = args.Contains("--no-dhcp");
var noDns = args.Contains("--no-dns");
var noV6 = args.Contains("--no-v6");
var nat64On = args.Contains("--nat64");

// DNS64 is opt-in: a synthesized AAAA is an address nothing can reach until a translator holding the
// same prefix exists, so turning synthesis on says something about the rest of the configuration. A bare
// --pref64 takes the prefix RFC 6147 §5.2 makes the default: "If no prefix is available, the algorithm
// MUST use the Well-Known Prefix 64:ff9b::/96".
Pref64Config? pref64 = null;
if (args.Contains("--pref64"))
{
    var prefArg = Host.OptionValue(args, "--pref64");
    pref64 = prefArg is null ? Pref64Config.WellKnown : Pref64Config.Parse(prefArg);
    if (pref64 is null)
    {
        Console.WriteLine($"[Router] --pref64 wants an IPv6 prefix with none of its host bits set and " +
                          $"one of the lengths RFC 6052 §2.2 allows ({string.Join(", ", Pref64.PrefixLengths)}), " +
                          $"got '{prefArg}'.");
        return 1;
    }
}

// The stateful translator is the second half of what --pref64 starts: RFC 6147 §5.2's synthesized AAAA is
// "an address nothing can reach until a translator holding the same prefix exists", and RFC 6146 §3.6.1
// generates both of the outgoing addresses from that prefix and from the pool the table answers on. With no
// prefix named, there is no realm to translate into and no address to embed a peer in.
if (nat64On && pref64 is null)
{
    Console.WriteLine("[Router] --nat64 needs --pref64 [<ipv6>/<len>] to name the prefix whose addresses it translates.");
    return 1;
}

// The same argument from the other side: without the IPv6 plane the LAN is never given a prefix, so no client
// on it has a route to an address inside Pref64::/n, and a stateful table that is offered no IPv6 binds no
// port. Refusing says that at the start rather than leaving it to a counter that stays at zero.
if (nat64On && noV6)
{
    Console.WriteLine("[Router] --nat64 with --no-v6 would translate traffic the LAN has no route to: " +
                      "the advertised prefix is what delivers a Pref64::/n packet to this program.");
    return 1;
}

// One --scope per subnet on the far side of a BOOTP relay agent, matched against the 'giaddr' the agent
// filled in. Kept as text until the LAN side is known, because the resolver a relayed client is pointed
// at defaults to this host's own address.
var scopeArgs = Host.OptionValues(args, "--scope");
if (noDhcp && scopeArgs.Count > 0)
{
    Console.WriteLine("[Router] --scope configures the lease server, which --no-dhcp turns off.");
    return 1;
}

if (noDns && pref64 is not null)
{
    Console.WriteLine("[Router] --pref64 configures the resolver's synthesis, which --no-dns turns off.");
    return 1;
}

// Refused rather than rounded: RFC 4787 REQ-5's two minutes is a floor the mapping timer MUST NOT fall
// under, so a shorter --udp-timeout is a configuration this program cannot honour at all.
var udpIdle = TimeSpan.FromSeconds(NatTable.UdpTimeoutDefaultSeconds);
if (Host.OptionValue(args, "--udp-timeout") is string udpTimeoutArg)
{
    if (!int.TryParse(udpTimeoutArg, out var udpSeconds) || udpSeconds < (int)NatTable.UdpTimeoutFloor.TotalSeconds)
    {
        Console.WriteLine($"[Router] --udp-timeout wants at least {(int)NatTable.UdpTimeoutFloor.TotalSeconds} seconds (RFC 4787 REQ-5), got '{udpTimeoutArg}'.");
        return 1;
    }
    udpIdle = TimeSpan.FromSeconds(udpSeconds);
}

var candidates = Host.DiscoverIpv4();
if (candidates.Count == 0)
{
    Console.WriteLine("[Router] No connected IPv4 interface found.");
    return 1;
}

Console.WriteLine("[Router] Interfaces:");
foreach (var candidate in candidates)
    Console.WriteLine($"[Router]   ifIdx={candidate.IfIdx,-4} {candidate.AddrText}/{candidate.Prefix,-2} gw={candidate.GatewayText,-15} {candidate.Media,-16} {candidate.Name}");

// Both sides are chosen the same way: exactly one candidate, or a refusal that lists them. Two
// interfaces with a default gateway is the ordinary state of a laptop with Wi-Fi associated and
// Ethernet plugged in, and which of them a wired client should leave through is not something
// enumeration order can know - it is the one thing this program cannot guess wrong in silence,
// because the NAT would still look healthy while sending everything out the other uplink.
var wanCandidates = candidates.Where(c => c.Gateway != 0).ToList();
var wan = wanArg is null
    ? wanCandidates.Count == 1 ? wanCandidates[0] : null
    : candidates.FirstOrDefault(c => c.AddrText == wanArg);
if (wan is null)
{
    if (wanArg is not null)
        Console.WriteLine($"[Router] --wan {wanArg} is not an address of any connected interface.");
    else if (wanCandidates.Count == 0)
        Console.WriteLine("[Router] No interface has an IPv4 default gateway; pass --wan <ipv4>.");
    else
    {
        Console.WriteLine("[Router] Several interfaces have a default gateway, so the WAN side is ambiguous. Pass --wan <ipv4>:");
        foreach (var candidate in wanCandidates)
            Console.WriteLine($"[Router]   {candidate.AddrText,-15} ifIdx={candidate.IfIdx,-4} gw={candidate.GatewayText,-15} {candidate.Media,-16} {candidate.Name}");
    }
    return 1;
}

var lanCandidates = candidates.Where(c => !ReferenceEquals(c, wan) && c.Gateway == 0).ToList();
var lan = lanArg is null
    ? lanCandidates.Count == 1 ? lanCandidates[0] : null
    : candidates.FirstOrDefault(c => c.AddrText == lanArg);
if (lan is null)
{
    if (lanArg is not null)
        Console.WriteLine($"[Router] --lan {lanArg} is not an address of any connected interface.");
    else if (lanCandidates.Count == 0)
        Console.WriteLine("[Router] No second interface to serve as the LAN side; plug one in or pass --lan <ipv4>.");
    else
    {
        // Enumeration order decides nothing here: a host with a Hyper-V switch has several
        // gateway-less interfaces and picking one silently would NAT into the wrong network.
        Console.WriteLine("[Router] Several interfaces have no gateway, so the LAN side is ambiguous. Pass --lan <ipv4>:");
        foreach (var candidate in lanCandidates)
            Console.WriteLine($"[Router]   {candidate.AddrText,-15} ifIdx={candidate.IfIdx,-4} {candidate.Name}");
    }
    return 1;
}

if (lanArg is not null && candidates.Count(c => c.AddrText == lanArg) > 1)
{
    // One address on two interfaces is a reachable state, not a hypothetical: an address add that the
    // store rejects can still have been written to it, so the LAN address ends up configured on both
    // the intended interface and another one. FirstOrDefault above and GetBestInterfaceEx behind IfIdx
    // would then disagree about which interface the LAN is, and the disagreement is invisible - every
    // path except forwarding works with the wrong index. Refuse instead of guessing.
    Console.WriteLine($"[Router] --lan {lanArg} is an address of more than one connected interface:");
    foreach (var candidate in candidates.Where(c => c.AddrText == lanArg))
        Console.WriteLine($"[Router]   ifIdx={candidate.IfIdx,-4} {candidate.Name}");
    Console.WriteLine("[Router] Remove the duplicate address; the LAN side has to be exactly one interface.");
    return 1;
}

// Both indices come from asking for the route to a local address, so a collision means the index
// resolution is wrong rather than the configuration odd. Refuse rather than NAT packets back onto
// the interface they arrived on.
if (lan.IfIdx == wan.IfIdx)
{
    Console.WriteLine($"[Router] LAN {lan.AddrText} and WAN {wan.AddrText} resolved to the same ifIdx {lan.IfIdx}.");
    return 1;
}
if (lan.Gateway != 0)
    Console.WriteLine($"[Router] Note: the LAN side {lan.Name} has its own gateway {lan.GatewayText}.");

Console.WriteLine($"[Router] LAN {lan.AddrText}/{lan.Prefix} ifIdx={lan.IfIdx} {lan.Media} ({lan.Name})");
Console.WriteLine($"[Router] WAN {wan.AddrText} ifIdx={wan.IfIdx} {wan.Media} ({wan.Name}), gateway {wan.GatewayText}");

// Per-interface forwarding is what puts a client's packet in front of this program at all: the forward
// layer sits downstream of the routing decision, so with it off the stack discards the packet before
// any handle is offered it, and the NAT has nothing to rewrite.
var lanForwarding = Host.QueryForwarding(lan.IfIdx);
var wanForwarding = Host.QueryForwarding(wan.IfIdx);
Console.WriteLine($"[Router] IPv4 forwarding: LAN={lanForwarding ?? "unknown"} WAN={wanForwarding ?? "unknown"}");
if (enableForwarding)
{
    Host.SetForwarding(lan.IfIdx);
    Host.SetForwarding(wan.IfIdx);
    Console.WriteLine($"[Router] IPv4 forwarding now: LAN={Host.QueryForwarding(lan.IfIdx)} WAN={Host.QueryForwarding(wan.IfIdx)}");
}
else if (lanForwarding == "Disabled" || wanForwarding == "Disabled")
{
    Console.WriteLine("[Router] Forwarding is off on one of the two, so a client's packet is discarded by the");
    Console.WriteLine("[Router]   stack before the forward layer offers it to any handle, and there is nothing to rewrite.");
    Console.WriteLine($"[Router]   Enable it with: Set-NetIPInterface -InterfaceIndex {lan.IfIdx} -Forwarding Enabled");
    Console.WriteLine($"[Router]                   Set-NetIPInterface -InterfaceIndex {wan.IfIdx} -Forwarding Enabled");
    Console.WriteLine("[Router]   or re-run with --enable-forwarding (needs elevation, per-interface, reversible).");
    return 1;
}

// The same switch for IPv6, and for the same reason: a delegated prefix only carries a client's packet
// once the stack is willing to forward it. Windows keeps the two families' settings apart, so the IPv4
// line above says nothing about this one. A disabled family is reported rather than refused: the prefix
// can still be delegated and advertised, and only the forwarding of what hosts then send is lost.
if (!noV6)
{
    var lan6Forwarding = Host.QueryForwarding(lan.IfIdx, "IPv6");
    var wan6Forwarding = Host.QueryForwarding(wan.IfIdx, "IPv6");
    Console.WriteLine($"[Router] IPv6 forwarding: LAN={lan6Forwarding ?? "unknown"} WAN={wan6Forwarding ?? "unknown"}");
    if (enableForwarding)
    {
        Host.SetForwarding(lan.IfIdx, "IPv6");
        Host.SetForwarding(wan.IfIdx, "IPv6");
        Console.WriteLine($"[Router] IPv6 forwarding now: LAN={Host.QueryForwarding(lan.IfIdx, "IPv6")} " +
                          $"WAN={Host.QueryForwarding(wan.IfIdx, "IPv6")}");
    }
    else if (lan6Forwarding == "Disabled" || wan6Forwarding == "Disabled")
    {
        Console.WriteLine("[Router] IPv6 forwarding is off on one of the two, so a LAN client's v6 packet is");
        Console.WriteLine("[Router]   discarded by the stack however good the advertised prefix is; --enable-forwarding sets it.");
    }
}

// The one conflict that leaves this program looking healthy: Windows' own NAT shares the forwarding path,
// and with sharing on both would rewrite the same packet, so traffic that works says nothing about which
// of the two carried it. Refuse rather than run under it, unless asked to take it over.
var ics = Host.QueryServiceState("SharedAccess");
if (ics == "Running")
{
    if (!stopIcs)
    {
        Console.WriteLine("[Router] Internet Connection Sharing is active (SharedAccess=Running). The driver's");
        Console.WriteLine("[Router]   documentation says not to use the forward layer alongside Windows NAT, and");
        Console.WriteLine("[Router]   two rewrites of the same packet cannot be told apart from the counters.");
        Console.WriteLine("[Router]   Stop it with: Stop-Service SharedAccess");
        Console.WriteLine("[Router]   or re-run with --stop-ics (needs elevation, reversed by Start-Service SharedAccess).");
        return 1;
    }
    ics = Host.StopService("SharedAccess");
    if (ics is "Running" or "StopPending")
    {
        Console.WriteLine($"[Router] --stop-ics was asked for and SharedAccess is still {ics}; not opening a handle under it.");
        Console.WriteLine("[Router]   Run Stop-Service SharedAccess yourself and read what it says - this");
        Console.WriteLine("[Router]   program prints that cmdlet's own words above, and a service that refuses");
        Console.WriteLine("[Router]   to stop is a Windows question, not one the NAT can answer.");
        return 1;
    }
    Console.WriteLine($"[Router] SharedAccess stopped for this run ({ics}).");

    // Stopping the service takes its own scope address off the interface it was sharing, and when that
    // interface is this run's LAN the address selected above was read from is the one that goes. Re-adding
    // it here is the difference between a client that gets a lease and one whose DHCP request has nowhere
    // to arrive; measured 2026-11-02 as three "Cannot bind 192.168.137.1" lines over an associated client.
    if (!Host.HasIpv4Address(lan.IfIdx, lan.AddrText))
    {
        Console.WriteLine($"[Router] {lan.AddrText} left ifIdx {lan.IfIdx} with the sharing stop; " +
                          $"putting it back as /{lan.Prefix}.");
        if (!Host.AddIpv4Address(lan.AddrText, lan.Prefix, lan.IfIdx))
        {
            Console.WriteLine("[Router]   the LAN has no address to answer DHCP and DNS on, so nothing a client");
            Console.WriteLine("[Router]   asks would be answered. Add it yourself with New-NetIPAddress and read");
            Console.WriteLine("[Router]   what it says, or pass --lan an address this program does not have to create.");
            return 1;
        }
    }
}
Console.WriteLine($"[Router] ICS: SharedAccess={ics ?? "unknown"}");

// Opened before any handle, so a WAN without a link-local address or a LAN without one is a line next to
// the interface listing rather than a task that died in silence. The loop itself starts further down,
// after every early return: a delegation installed by a run that then refused to start would leave an
// address behind with nothing behind it.
var v6 = noV6 ? null : V6Router.Open(wan, lan);

// Read at the moment a port is picked rather than once at startup, because the socket this program cares
// most about - the resolver's upstream one - is not bound yet here, and its ephemeral port comes out of the
// same 49152+16384 span the NAT allocates from.
var localPorts = new LocalPorts();
var table = new NatTable(wan.Addr, lan.Addr, lan.Mask, udpIdle: udpIdle, localPorts: localPorts.Held);
Console.WriteLine($"[Router] NAT: UDP mapping timer {(int)udpIdle.TotalSeconds}s, " +
                  "mapped ports preserve the internal port's parity, and a port this host holds is never mapped");
table.Expired += (key, natPort, idle) =>
    Console.WriteLine($"[Router] EXPIRE proto={key.Proto} {NatTable.FormatAddress(key.ClientIp)}:{key.ClientPort} nat={natPort} idle={idle.TotalMinutes:0.#}min");

// The stateful PLAT, opt-in. RFC 6146 §3.5.1.1's first bullet read against a single interface address makes
// the pool this table answers on the same one the IPv4 NAT writes, and §3.5.1.1's last bullet lets one number
// live in the UDP BIB here and in the IPv4 table's map at the same time - which it cannot do at this host,
// where a reply to that port would have two owners. So each allocator is shown the other's claims and takes
// none of them.
Nat64? nat64 = null;
var natPath = Siit.PathMtu.Unknown;
if (nat64On)
{
    nat64 = new Nat64(pref64!, System.Net.IPAddress.Parse(NatTable.FormatAddress(wan.Addr)),
        localPorts: localPorts.Held, otherMapped: proto => table.MappedPorts(proto));
    table.OtherMapped = proto => nat64.MappedPorts(proto);
    // RFC 7915 §4.2 and §5.2 give the Packet Too Big message the MTU of the next hop on each side, so the two
    // are read from the interface rather than assumed: the WAN here is a phone hotspot whose link is 1492.
    natPath = new Siit.PathMtu((int)(Host.QueryMtu(wan.IfIdx, "IPv4") ?? (uint)Siit.PathMtu.Unknown.Ipv4NextHop),
        (int)(Host.QueryMtu(wan.IfIdx, "IPv6") ?? (uint)Siit.PathMtu.Unknown.Ipv6NextHop));
    Console.WriteLine($"[Router] NAT64: RFC 6146 BIB/STE table on {NatTable.FormatAddress(wan.Addr)} under " +
                      $"{pref64!.Prefix}/{pref64.PrefixLength}; UDP {Nat64.UdpDefault.TotalMinutes:0} min, " +
                      $"TCP {Nat64.TcpEstablished.TotalMinutes:0}+{Nat64.TcpTransitory.TotalMinutes:0} min, " +
                      $"query {Nat64.IcmpQueryLifetime.TotalSeconds:0} s, path MTU v4={natPath.Ipv4NextHop} " +
                      $"v6={natPath.Ipv6NextHop}. A fragment after the first is translated from the record its " +
                      "first fragment left (RFC 6146 §3.4); the datagram is never reassembled here.");
}

// The pool and the two listeners exist so a device plugged into the LAN side answers to something:
// an address from the pool, this host as its router and resolver, and the option 12 hostname plus the
// query log as the identity a remote client has no PID for.
DhcpServer? dhcp = null;
if (!noDhcp)
{
    // Measured on a /28 LAN side: a pool at network+100 is outside the subnet, so the default has to
    // be derived from the mask rather than assumed to be a /24.
    var network = lan.Addr & lan.Mask;
    var room = DhcpConfig.PoolRoom(lan.Addr, lan.Mask);
    var poolText = poolArg ?? (room >= 1 ? $"{NatTable.FormatAddress(network + 1)}/{Math.Min(50, room)}" : null);
    if (poolText is null)
    {
        Console.WriteLine($"[Router] {lan.AddrText}/{lan.Prefix} has no room for a pool beyond this host's own address.");
        Console.WriteLine("[Router]   Pass --pool <ipv4>/<count>, or --no-dhcp to run without a lease server.");
        return 1;
    }
    var poolParts = poolText.Split('/');
    if (poolParts.Length != 2 || !int.TryParse(poolParts[1], out var poolCount) || poolCount <= 0)
    {
        Console.WriteLine($"[Router] --pool wants <ipv4>/<count>, got '{poolText}'.");
        return 1;
    }
    var poolStart = NatTable.ParseAddress(poolParts[0]);
    if (!DhcpConfig.PoolFitsSubnet(poolStart, poolCount, lan.Addr, lan.Mask))
    {
        Console.WriteLine($"[Router] pool {poolText} is outside the LAN side {lan.AddrText}/{lan.Prefix}.");
        Console.WriteLine("[Router]   Every leased address has to be reachable on the interface that served it.");
        return 1;
    }

    var scopes = new List<DhcpScope>();
    foreach (var text in scopeArgs)
    {
        if (!DhcpScope.TryParse(text, lan.Addr, out var scope, out var why))
        {
            Console.WriteLine($"[Router] --scope '{text}' is not usable: {why}");
            return 1;
        }
        // Scopes are matched in the order they were given, so a subnet named twice would leave the second
        // one unreachable rather than adding anything.
        if (scopes.Any(earlier => earlier.Network == scope.Network && earlier.SubnetMask == scope.SubnetMask))
        {
            Console.WriteLine($"[Router] --scope '{text}' names a subnet an earlier --scope already covers.");
            return 1;
        }
        scopes.Add(scope);
    }

    dhcp = new DhcpServer(new DhcpConfig
    {
        ServerAddress = lan.Addr,
        SubnetMask = lan.Mask,
        PoolStart = poolStart,
        PoolCount = poolCount,
        LeaseTime = TimeSpan.FromMinutes(leaseMinutes),
        RelayScopes = scopes,
    });
    foreach (var scope in scopes)
        Console.WriteLine($"[Router] relay scope {NatTable.FormatAddress(scope.Network)}" +
                          $" mask {NatTable.FormatAddress(scope.SubnetMask)} " +
                          $"pool {NatTable.FormatAddress(scope.PoolStart)}+{scope.PoolCount} " +
                          $"router {NatTable.FormatAddress(scope.Router)} " +
                          $"dns {NatTable.FormatAddress(scope.Dns)}");
    if (scopes.Count > 0)
        Console.WriteLine($"[Router] A relay agent has to be told to forward to {lan.AddrText}:{DhcpPorts.ServerPort}, " +
                          $"which is where the listener is bound.");
    dhcp.RelayWithoutScope += giaddr => Console.WriteLine(
        $"[Router] Relayed request with giaddr {NatTable.FormatAddress(giaddr)} matches no --scope, so it is not answered.");
}

// --no-dns still skips the resolver lookup: the PowerShell call behind it is not free, and asking
// what the WAN interface's DNS server is would be pointless when nothing is going to forward to it.
var upstream = dnsArg is not null ? NatTable.ParseAddress(dnsArg)
    : noDns ? null
    : Host.QueryDnsServer(wan.IfIdx);
if (upstream is null && !noDns)
{
    Console.WriteLine($"[Router] No DNS server configured on {wan.Name}, so there is nothing to forward to.");
    Console.WriteLine("[Router]   Pass --dns <ipv4>, or --no-dns to run without a resolver at all.");
    return 1;
}

DnsServer? dns = null;
UdpClient? upstreamSocket = null;
if (!noDns && upstream is uint resolver)
{
    // One socket for the whole run, and one receive loop on it: Services.UpstreamResolver files an
    // answer under the transaction id this server put on the query, so answers for different clients'
    // questions can be in flight at once without being confused for each other.
    upstreamSocket = new UdpClient(AddressFamily.InterNetwork);
    dns = new DnsServer(Services.Upstream(resolver, upstreamSocket, table), name => dhcp?.AddressOfHostName(name),
        pref64: pref64);
    // Subscribed here rather than in the listener loop: the resolver has one UDP loop per family and both
    // run the same code, so an event attached per loop would print every query twice.
    dns.Queried += (name, type, client) => Console.WriteLine($"[Router] dns {client} -> {name} type={type}");
    // The advertisements then name this host's own LAN address as the recursive resolver, so the answer a
    // LAN client gets is one this resolver built - which is the only place the ECH configuration is taken
    // out of it. The same advertisement carries RFC 8781's PREF64 option when synthesis is on, so that a
    // host which forms addresses for itself uses the prefix these answers were formed with.
    if (v6 is { } v6Advertising)
    {
        v6Advertising.AnswersDnsItself = true;
        v6Advertising.Pref64 = pref64;
    }
    Console.WriteLine($"[Router] DNS on {lan.AddrText}:{DnsPorts.ServerPort}, " +
                      $"upstream {NatTable.FormatAddress(resolver)} from this host's UDP " +
                      $"{((System.Net.IPEndPoint)upstreamSocket.Client.LocalEndPoint!).Port}");
    if (pref64 is { } prefix)
    {
        Console.WriteLine($"[Router] DNS64 answers a AAAA question that has no AAAA of its own from the " +
                          $"A records, under Pref64 {prefix.Prefix}/{prefix.PrefixLength}.");
        Console.WriteLine(v6 is null
            ? "[Router]   --no-v6 leaves the advertisements out, so a client learns that prefix only from " +
              "the answers themselves."
            : "[Router]   The Router Advertisements carry the same prefix in RFC 8781's PREF64 option.");
    }
}

// The forward layer is where a packet this host routes rather than delivers is diverted; the network layer
// is documented as packets to and from the local machine, so traffic that reaches past this host never
// appears there at all. Upstream documents Network.IfIdx as the interface a packet arrived on when it is
// inbound and the one it is to be sent on when it is outbound, and at this layer the routing decision has
// already happened, so the index names the egress - measured on this host, the transit packets that were
// seen arrived with the outbound bit set and the WAN interface's index. It is not what decides a packet's
// direction, and the packet's own addresses are what decide it. It is also the condition the filter asks
// about, which is the same thing the sniff handle reports as take=.
// Impostor is excluded so a reinjection is never handed back to be rewritten again: the passthrough path
// sends a packet on unchanged, and a second pass would send it on again forever.
// --nat64 is what adds the second family, and the cost is stated rather than hidden: with it on, every
// forwarded IPv6 TCP, UDP and ICMPv6 packet is taken by this handle and put back, including the ones whose
// destination is outside the prefix and which Windows used to forward on its own. WinDivert's language
// matches an IPv6 address exactly, not by prefix, so the prefix test can only live in the loop below.
// Without the flag the filter is the one the router has been run with.
var filter = $"(ifIdx == {wan.IfIdx} or ifIdx == {lan.IfIdx}) and " +
             (nat64 is null ? "ip and (tcp or udp or icmp)"
                             : "(ip and (tcp or udp or icmp) or ipv6 and (tcp or udp or icmpv6))") +
             " and not impostor";

using var cts = new CancellationTokenSource();
// Assigned as each handle opens; the handler below runs on its own thread and may fire while a loop is
// blocked inside the driver.
WinDivertHandle? forwardHandle = null;
WinDivertHandle? replyHandle = null;
WinDivertHandle? forwardTrace = null;
WinDivertHandle? netTrace = null;
WinDivertHandle? v6ForwardTrace = null;
WinDivertHandle? v6NetTrace = null;
WinDivertHandle? v6ReplyHandle = null;
// One definition, used by Ctrl+C and by a faulted loop: set the token, then make the driver stop queuing
// and end whatever call is blocked inside it. The handles are shut down from here rather than from the
// loops' own finally, because a thread blocked in WinDivertRecv never observes the token: cancellation
// that only flips the flag leaves the process alive with its handles still diverting. A diverted packet
// that is never reinjected is not bounced back to the sender - it is dropped - so that state takes down
// every flow the filters match, including this host's own inbound high-port traffic.
void Abort()
{
    cts.Cancel();
    forwardHandle?.Shutdown(ShutdownMode.Recv);
    replyHandle?.Shutdown(ShutdownMode.Recv);
    v6ReplyHandle?.Shutdown(ShutdownMode.Recv);
    forwardTrace?.Shutdown(ShutdownMode.Recv);
    netTrace?.Shutdown(ShutdownMode.Recv);
    v6ForwardTrace?.Shutdown(ShutdownMode.Recv);
    v6NetTrace?.Shutdown(ShutdownMode.Recv);
}
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    Abort();
    // Anything still stuck after that is not going to be fixed by waiting: a console write that has
    // blocked (a selection in the window is enough) stops a capturing loop just as completely, and the
    // process must not outlive the ability to serve the packets it took.
    _ = Task.Run(async () =>
    {
        await Task.Delay(TimeSpan.FromSeconds(3));
        Console.WriteLine("[Router] shutdown did not complete in 3 s; exiting to release the diverted traffic.");
        Environment.Exit(2);
    });
};

// Started before the driver is opened: a device that can reach this host but gets no lease is a
// different problem from a packet that never leaves, and binding first tells you which one you have.
UdpClient? dhcpSocket = dhcp is null ? null
    : Services.OpenListener(Host.ToIpAddress(lan.Addr), DhcpPorts.ServerPort, true);
UdpClient? dnsSocket = dns is null ? null
    : Services.OpenListener(Host.ToIpAddress(lan.Addr), DnsPorts.ServerPort, false);
// The TCP half of the resolver, for the retry RFC 1035 §4.2.1 sends there once a UDP answer came back
// with TC set. Bound separately because a client that never sees TC never opens this connection.
TcpListener? dnsTcp = dns is null ? null
    : Services.OpenTcpListener(Host.ToIpAddress(lan.Addr), DnsPorts.ServerPort);

// The probes are made here because the loops below are what answer them, and a listener has to be running
// before anything is put on the wire for it. A port that never bound is not probed: the answer would be
// about a socket that is not there, not about the filter.
var probeSource = LanProbe.ProbeSource(lan.Addr, lan.Mask);
LanProbe? dhcpProbe = dhcp is null || dhcpSocket is null ? null
    : new LanProbe("dhcp", DhcpPorts.ServerPort, probeSource, NextToken());
LanProbe? dnsProbe = dns is null || dnsSocket is null ? null
    : new LanProbe("dns", DnsPorts.ServerPort, probeSource, NextToken());
var probePorts = new List<ushort>();
if (dhcpProbe != null) probePorts.Add(dhcpProbe.DestinationPort);
if (dnsProbe != null) probePorts.Add(dnsProbe.DestinationPort);

const string LanRuleName = "router-lan-in";
const string DnsTcpRuleName = "router-dns-tcp-in";
var lanRuleOwned = false;
var dnsTcpRuleOwned = false;
// Set once by whichever release path runs first - Main's own end, the process-exit handler, or the console
// close handler, which arrives on a thread of its own while this thread is still running.
var lanRulesReleased = 0;

// Registered before anything is added, because the store call that adds a rule takes a few hundred
// milliseconds and a close landing in that window would otherwise end the run with the rule in and no one
// left to take it out. The release at the end of this file needs Main to reach it, and the interrupt
// handler's own Environment.Exit does not: measured 2026-11-02, Environment.Exit does run a ProcessExit
// handler and a console close runs none at all, so this covers the watchdog exit.
AppDomain.CurrentDomain.ProcessExit += (_, _) => ReleaseLanRules(quiet: true);

// The close that no exit handler sees gets a Win32 control handler instead; ConsoleClose carries the
// measurements that make it worth having - its own thread, about 5 s of it, and the firewall call working
// from there. Quiet, because the run is ending while this runs, and the store's count is the witness.
if (!ConsoleClose.Register(() => ReleaseLanRules(quiet: true)))
    Console.WriteLine("[Router] no console control handler could be registered (no console attached); " +
                      "closing this window leaves the rules in the store for the next run to report");

if (probePorts.Count > 0)
{
    // Printed for the same reason the proxy prints it: a run that ends on a filtered port is easier to
    // read if the policy the packet met is on the record. It is not the verdict - the probe below is.
    Console.WriteLine($"[Router] Firewall: {InboundFirewall.EnabledState()}");
    lanRuleOwned = AllowIn(LanRuleName, InboundFirewall.ProtoUdp, "UDP", string.Join(',', probePorts),
        "Inbound UDP to Router's lease server and resolver, which a LAN client reaches from its own address");
    // The retry a truncated answer sends goes under its own name, so a run whose UDP ports were opened by
    // hand is not claimed to have opened this one, and only the resolver is behind this port.
    if (dnsTcp != null)
        dnsTcpRuleOwned = AllowIn(DnsTcpRuleName, InboundFirewall.ProtoTcp, "TCP", DnsPorts.ServerPort.ToString(),
            "Inbound TCP to Router's resolver, where a client retries the answer a UDP one was truncated for");
}
else if (allowLanIn)
{
    Console.WriteLine("[Router] --allow-lan-in concerns the LAN listeners, and none is running; nothing is added.");
}

bool AllowIn(string name, int protocol, string protocolName, string ports, string description)
{
    if (InboundFirewall.Exists(name))
    {
        // Left in place because README names these two display names for a hand-made persistent rule too, so
        // this program cannot tell its own residue from the operator's choice. What does strand a rule here
        // is taskkill /F: measured 2026-11-02, it delivers no notification of any kind - no signal, no
        // handler, no chance to answer - so the residue is reachable only from the next start, and the line
        // says what clears it.
        Console.WriteLine($"[Router] '{name}' is already in the store; left in place, and not removed on exit. " +
                          $"If it is what a killed run left behind: Remove-NetFirewallRule -DisplayName '{name}'");
        return false;
    }
    if (!allowLanIn) return false;
    // A close that lands while this run is still starting up has already released, and nothing will run
    // after the process dies: adding now would strand the rule with no one left to take it out.
    if (Volatile.Read(ref lanRulesReleased) != 0)
    {
        Console.WriteLine($"[Router] {name} not added: this run's rules were already released by a close");
        return false;
    }
    var added = InboundFirewall.Add(name, description, protocol, ports);
    Console.WriteLine(added
        ? $"[Router] Added '{name}' for {protocolName} {ports}; removed when this run ends"
        : $"[Router] --allow-lan-in did not put '{name}' in the store (needs elevation)");
    return added;
}

if (dhcp is { } dhcpServer && dhcpSocket is { } dhcpPort && dhcpProbe is { } dhcpWitness)
    _ = Task.Run(() => Services.RunDhcp(dhcpPort, dhcpServer, lan.Addr, dhcpWitness, cts.Token));
if (dns is { } dnsServer && dnsSocket is { } dnsPort)
    _ = Task.Run(() => Services.RunDns(dnsPort, dnsServer, dnsProbe, cts.Token));
if (dns is { } dnsResolver && dnsTcp is { } dnsTcpListener)
    _ = Task.Run(() => Services.RunDnsTcp(dnsTcpListener, dnsResolver, lan.AddrText, cts.Token));

// The resolver's IPv6 half, which cannot be opened with the pair above: the address it binds to is the
// one the delegation installs on the LAN interface, and a bind to an address no interface holds fails.
// Both families are served by the one DnsServer, so the cache, the upstream socket and the query line are
// shared rather than doubled, and the answer a v6 client gets is the same one - ECH configuration taken
// out - that a v4 client gets. The listeners are closed from the same event with a null address:
// V6Router.Run's finally always reaches Withdraw, so their lifetime is the address's.
UdpClient? dnsV6 = null;
TcpListener? dnsV6Tcp = null;
if (v6 is { } v6Listener && dns is { } v6Dns)
{
    v6Listener.ResolverAddressChanged += address =>
    {
        dnsV6?.Dispose();
        dnsV6 = null;
        dnsV6Tcp?.Stop();
        dnsV6Tcp = null;
        if (address is null) return true;
        dnsV6 = Services.OpenListener(address, DnsPorts.ServerPort, false);
        dnsV6Tcp = Services.OpenTcpListener(address, DnsPorts.ServerPort);
        if (dnsV6 is { } v6Udp) _ = Task.Run(() => Services.RunDns(v6Udp, v6Dns, null, cts.Token));
        if (dnsV6Tcp is { } v6Tcp)
            _ = Task.Run(() => Services.RunDnsTcp(v6Tcp, v6Dns, $"[{address}]", cts.Token));
        return dnsV6 is not null;
    };
}

// One datagram at each listener that is running, from an address inside the LAN subnet, and then the wait
// for the loop that owns that port to report it. Unlike the relay's TCP probe there is nothing to read off
// the stack here: a datagram the filter lets through is delivered, so the arrival is the whole answer and a
// missing one is the filter's doing rather than a handshake that never completed.
if (probePorts.Count > 0)
{
    // Remembered per port, because a port whose packet never went out has no verdict either way.
    var asked = new List<(LanProbe probe, bool sent)>();
    ushort? synToken = null;
    var synSent = false;
    try
    {
        // The injection shape tools/inject puts a substitute client's packet in with, and the one whose TCP
        // form left a SYN-RECEIVED row on this host's AP adapter. `ip` rather than `udp` because the TCP
        // probe below goes out through this same handle.
        using var sender = new WinDivertHandle("ip and not impostor", Layer.Network, 200, Flag.Sniff | Flag.SendOnly);
        if (dhcpProbe is { } dp) asked.Add((dp, SendToListener(sender, dp.Build(lan.Addr, DhcpPorts.ClientPort))));
        if (dnsProbe is { } np) asked.Add((np, SendToListener(sender, np.Build(lan.Addr, LanProbe.EphemeralSourcePort))));
        if (dnsTcp != null)
        {
            synToken = NextToken();
            synSent = SendToListener(sender, RelayProbe.BuildSyn(Host.ToIpAddress(probeSource),
                Host.ToIpAddress(lan.Addr), synToken.Value, DnsPorts.ServerPort), "TCP");
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[Router] inbound probe handle refused, so whether a client's datagram reaches " +
                          $"{lan.AddrText} is unknown: {ex.GetType().Name}: {ex.Message}");
    }

    if (asked.Any(what => what.sent))
    {
        for (var tick = 0;
             tick < 15 && !asked.All(what => !what.sent || what.probe.Arrivals > 0);
             tick++) await Task.Delay(100);

        var filteredPorts = new List<ushort>();
        foreach (var (probe, sent) in asked)
        {
            if (!sent)
            {
                Console.WriteLine($"[Router] inbound probe: the {probe.Name} packet did not go out, so {probe.DestinationPort} " +
                                  "stays unknown and the run continues");
                continue;
            }
            if (probe.Arrivals > 0)
            {
                Console.WriteLine($"[Router] inbound probe: {probe.Name} reached its listener, so a datagram from " +
                                  $"{NatTable.FormatAddress(probe.Source)} gets through to {lan.AddrText}:{probe.DestinationPort}");
            }
            else
            {
                filteredPorts.Add(probe.DestinationPort);
                Console.WriteLine($"[Router] inbound probe: {probe.Name} never arrived, so a client's datagram to " +
                                  $"{lan.AddrText}:{probe.DestinationPort} is filtered before it reaches this program");
            }
        }

        if (filteredPorts.Count > 0)
        {
            foreach (var port in filteredPorts)
                foreach (var name in InboundFirewall.BlockCandidates(InboundFirewall.ProtoUdp, port).Take(3))
                    Console.WriteLine($"[Router]   UDP {port}: block rule that could outrank an allow here: {name}");
            if (InboundFirewall.Exists(LanRuleName))
                Console.WriteLine($"[Router]   '{LanRuleName}' is in the store and the port stays filtered, so this run ends");
            else
            {
                Console.WriteLine($"[Router]   Add it with: New-NetFirewallRule -DisplayName '{LanRuleName}' -Direction Inbound");
                Console.WriteLine($"[Router]                  -Protocol UDP -LocalPort {string.Join(',', probePorts)} -Action Allow -Profile Any");
                Console.WriteLine("[Router]   or re-run with --allow-lan-in (needs elevation, removed again when the run ends).");
            }

            if (lanRuleOwned)
            {
                InboundFirewall.Remove(LanRuleName);
                lanRuleOwned = false;
            }
            // This return is a run end too, and a rule added under --allow-lan-in is this run's to take back.
            if (dnsTcpRuleOwned)
            {
                InboundFirewall.Remove(DnsTcpRuleName);
                dnsTcpRuleOwned = false;
            }
            dhcpSocket?.Dispose();
            dnsSocket?.Dispose();
            dnsTcp?.Stop();
            return 1;
        }
    }
    else if (asked.Count > 0)
    {
        Console.WriteLine("[Router] inbound probe: nothing went out, so a LAN client may still be filtered; the run continues");
    }

    // The TCP leg of the resolver, judged the way the relay's is: a lone SYN never reaches an accept
    // queue, so the row the stack keeps for it in its own connection table is the reading (RFC 9293 §3.5
    // Figure 6 puts the receiver in SYN-RECEIVED on the SYN alone). It reports and does not end the run:
    // an answer over the UDP ceiling still reaches the client cut and with TC set, so a filtered port
    // here costs the retry after it, not the answer.
    if (dnsTcp != null && synToken is ushort token)
    {
        if (!synSent)
        {
            Console.WriteLine($"[Router] inbound probe: the TCP SYN did not go out, so whether a client reaches " +
                              $"{lan.AddrText}:{DnsPorts.ServerPort} over TCP is unknown and the run continues");
        }
        else
        {
            var answered = false;
            var read = false;
            for (var tick = 0; tick < 15 && !answered; tick++)
            {
                await Task.Delay(100);
                if (RelayProbe.ReadTcpTable() is not { } halfOpen) continue;
                read = true;
                answered = RelayProbe.Answers(halfOpen, Host.ToIpAddress(probeSource), token,
                    Host.ToIpAddress(lan.Addr), DnsPorts.ServerPort);
            }

            if (answered)
                Console.WriteLine($"[Router] inbound probe: a SYN from {NatTable.FormatAddress(probeSource)} left a " +
                                  $"half-open row on {lan.AddrText}:{DnsPorts.ServerPort}, so the retry after a " +
                                  "truncated answer reaches the resolver");
            else if (!read)
                Console.WriteLine("[Router] inbound probe sent, but the connection table could not be read, so whether that SYN" +
                                  " reached the resolver's TCP port is unknown; the run continues as if it had");
            else
            {
                Console.WriteLine($"[Router] inbound probe: no half-open row, so a client's TCP SYN to " +
                                  $"{lan.AddrText}:{DnsPorts.ServerPort} is filtered. An oversized answer still arrives" +
                                  " cut with TC set; only the retry that follows it cannot.");
                foreach (var name in InboundFirewall.BlockCandidates(InboundFirewall.ProtoTcp, DnsPorts.ServerPort).Take(3))
                    Console.WriteLine($"[Router]   TCP {DnsPorts.ServerPort}: block rule that could outrank an allow here: {name}");
                if (InboundFirewall.Exists(DnsTcpRuleName))
                    Console.WriteLine($"[Router]   '{DnsTcpRuleName}' is in the store and the port stays filtered");
                else
                {
                    Console.WriteLine($"[Router]   Add it with: New-NetFirewallRule -DisplayName '{DnsTcpRuleName}'");
                    Console.WriteLine($"[Router]                  -Direction Inbound -Protocol TCP -LocalPort {DnsPorts.ServerPort} " +
                                      "-Action Allow -Profile Any");
                    Console.WriteLine("[Router]   or re-run with --allow-lan-in (needs elevation, removed again when the run ends).");
                }
            }
        }
    }
}

static ushort NextToken() => unchecked((ushort)Random.Shared.Next(1, ushort.MaxValue + 1));

// Inbound on purpose: Flags is the only field that says which way a packet is going, and the interface is
// the one a client's datagram would arrive on, which is what strong-host receive asks for (RFC 1122
// §3.3.4.2). Everything else in the address is cleared first, so no leftover field decides anything.
unsafe bool SendToListener(WinDivertHandle sender, byte[] packet, string label = "UDP")
{
    var buffer = Marshal.AllocHGlobal(packet.Length);
    var address = Marshal.AllocHGlobal(ADDR_SIZE);
    try
    {
        Marshal.Copy(packet, 0, buffer, packet.Length);
        var addr = (Address*)address;
        new Span<byte>(addr, ADDR_SIZE).Clear();
        addr->Flags = AddressFlag.None;
        addr->IfIdx = lan.IfIdx;
        sender.CalcChecksums((void*)buffer, packet.Length, addr);
        var went = sender.Send((void*)buffer, packet.Length, null, addr);
        // The endpoints are read back out of the bytes that went, not from the arguments, so what is on the
        // record is the packet rather than the intention. Both probes put the source port at octet 20 and
        // the destination at 22 behind a 20-octet internet header, so this reads either.
        string Endpoint(int addressOffset, int portOffset) =>
            $"{NatTable.FormatAddress(BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(addressOffset, 4)))}" +
            $":{BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(portOffset, 2))}";
        Console.WriteLine($"[Router] inbound probe: {label} {Endpoint(12, 20)} -> {Endpoint(16, 22)} " +
                          $"ifIdx={addr->IfIdx} sent={went}");
        return went;
    }
    finally
    {
        Marshal.FreeHGlobal(buffer);
        Marshal.FreeHGlobal(address);
    }
}

WinDivertHandle? sniffer = null;
WinDivertHandle? netSniffer = null;
WinDivertHandle? v6Sniffer = null;
WinDivertHandle? v6NetSniffer = null;
if (trace)
{
    // Sniff-only, so it observes without removing anything, and above the main handle in priority, so it
    // is asked about a packet first: this is the view of the client's packet as it actually arrives at
    // the forwarding path, before any rewrite. What it cannot see is the reinjection itself, because a
    // packet a handle injects is offered only to the handles below it - so a packet that shows up here
    // and never again is one the main handle took, which is the difference between "eaten" and "never
    // arrived" that the counters alone cannot make. tools/inject --fwd watches the same layer.
    var traceHandle = new WinDivertHandle("ip and (tcp or udp or icmp)", Layer.Forward, 100, Flag.Sniff | Flag.RecvOnly);
    sniffer = traceHandle;
    forwardTrace = traceHandle;
    // The second layer is for the reply leg, and a live run settled it: the upstream text names the forward
    // layer as packets passing through the machine and the network layer as packets to and from it, and a
    // SNAT reply is addressed to this host's own WAN address, so the routing decision classifies it as
    // local delivery. Measured, the forward-layer window held no inbound packet at all while the network
    // layer showed the answers arriving at the WAN address - which is why dnat=0 is a capture-point fact
    // here and not a defect in the DNAT branch.
    netSniffer = new WinDivertHandle("inbound and ip and (tcp or udp or icmp)", Layer.Network, 100, Flag.Sniff | Flag.RecvOnly);
    var netTraceHandle = netSniffer;
    netTrace = netSniffer;
    // The IPv6 legs are separate handles rather than a widened filter, for the reason the v4 pair already
    // learned: a shared budget is spent by whatever is busiest, and the v6 question is answered by a packet
    // that may arrive once a minute. `ipv6` is the filter language's name for the family (`ip6` is a bad
    // token), and `icmpv6` is what puts Neighbour Discovery and Packet Too Big on the screen - the two
    // messages a silent v6 path is diagnosed from.
    v6Sniffer = new WinDivertHandle("ipv6 and (tcp or udp or icmpv6)", Layer.Forward, 100, Flag.Sniff | Flag.RecvOnly);
    v6ForwardTrace = v6Sniffer;
    v6NetSniffer = new WinDivertHandle("inbound and ipv6 and (tcp or udp or icmpv6)", Layer.Network, 100, Flag.Sniff | Flag.RecvOnly);
    v6NetTrace = v6NetSniffer;
    Console.WriteLine($"[Router] Trace on: sniffing the forward layer and the network layer inbound, first {traceCount} packets on each; " +
                      $"the main handle accepts ifIdx {lan.IfIdx} or {wan.IfIdx}");
    // The two runs are read against each other, so the difference in what they print is worth stating: the
    // host's own traffic is a large majority of what the network layer is offered, and printing it spent the
    // whole budget on a live run without a single client packet reaching the screen.
    Console.WriteLine("[Router]   [Trace fwd] = what the main handle is offered. [Trace net] = only the LAN subnet's");
    Console.WriteLine("[Router]   packets and the answers to mapped ports, so a client's reply showing on one layer");
    Console.WriteLine("[Router]   and not the other is the capture point, not the decision tree.");
    // IPv6 has no rewrite to observe, only a forwarding decision, and the two legs are not the two halves
    // of one path: a forwarded packet is never addressed to this host, so the network layer is never
    // offered it. Measured on a live run: a client's packet prints once on v6fwd at its egress interface -
    // the request at the WAN index, the answer at the LAN one - while v6net stays silent for the whole
    // flow, and a transit packet Windows drops prints on neither leg. The client's own reply is therefore
    // the end-to-end judge; this pair says where a packet went, not whether the path exists.
    Console.WriteLine($"[Router]   [Trace v6fwd] = IPv6 Windows is forwarding, one line per packet at its egress");
    Console.WriteLine("[Router]   interface: a client's request at the WAN index, its answer at the LAN one. A transit");
    Console.WriteLine("[Router]   packet Windows drops prints on neither leg, so the client's reply is the end-to-end");
    Console.WriteLine($"[Router]   judge. [Trace v6net] = IPv6 addressed to this host arriving on the LAN (ifIdx {lan.IfIdx}),");
    Console.WriteLine("[Router]   which is where a client reaching this process' own listener shows. No take= on these");
    Console.WriteLine("[Router]   two: the main filter is `ip`, IPv4, so it takes no IPv6 packet - the v6 path is");
    Console.WriteLine("[Router]   Windows' own forwarding plus the on-link route the delegated /64 install brings.");
    _ = Task.Run(() => Host.TraceLoop(traceHandle, cts.Token, traceCount, "fwd", true,
        lan.Addr, lan.Mask, lan.IfIdx, wan.IfIdx, table.IsMappedPort));
    _ = Task.Run(() => Host.TraceLoop(netTraceHandle, cts.Token, traceCount, "net", false,
        lan.Addr, lan.Mask, lan.IfIdx, wan.IfIdx, table.IsMappedPort));
    _ = Task.Run(() => Host.TraceLoop(v6Sniffer, cts.Token, traceCount, "v6fwd", true,
        lan.Addr, lan.Mask, lan.IfIdx, wan.IfIdx, table.IsMappedPort, v6: true));
    _ = Task.Run(() => Host.TraceLoop(v6NetSniffer, cts.Token, traceCount, "v6net", false,
        lan.Addr, lan.Mask, lan.IfIdx, wan.IfIdx, table.IsMappedPort, v6: true));
}

WinDivertHandle divert;
try
{
    // No Sniff, deliberately: a capturing handle takes the packet out of the forwarding path, which is
    // why the loop below reinjects on every branch, including the one that changes nothing. A sniffed
    // copy would leave the original to be forwarded with the client's own un-routable source address,
    // and a RecvOnly handle cannot send the rewrite at all.
    divert = new WinDivertHandle(filter, Layer.Forward, -100, Flag.None);
    forwardHandle = divert;
}
catch (Exception ex)
{
    Console.WriteLine($"[Router] WinDivertOpen failed: {ex.Message}");
    Console.WriteLine("[Router] Needs elevation - the driver is loaded on open.");
    return 1;
}

Console.WriteLine($"[Router] Filter: {filter}");
// Measured against the documented rule, not assumed: higher values are higher priorities, so -100 is
// below the proxy's 0 among the handles that share a layer. It does not order this handle against
// TlsMitm at all, because the two are on different layers and a transit packet is only ever offered to
// the handles on the forward one. That is the consequence of this layer choice and it is stated rather
// than tuned away: a flow this host merely forwards is invisible to the proxy's network-layer capture,
// so making the proxy see one is a separate piece of work, not a priority number.
Console.WriteLine("[Router] Layer.Forward, priority -100, capturing rather than sniffing. Ctrl+C to stop.");

// The reply leg, at the layer the measurement put it on. A packet whose destination is this host's own WAN
// address is local delivery rather than forwarding, so the forward handle above is never asked about it and
// no rewrite of the DNAT branch can change that: the answer has to be taken where it appears.
// The filter is bounded twice over - to that address and to the mapped port range - because the host's own
// inbound traffic shares both the layer and the interface index, and an unbounded inbound handle here would
// divert every packet this machine receives. What it does take is handed to the same Translate as the
// outbound leg, so there is one decision tree rather than a second one for the LAN side.
// The address is a clause rather than a constant, and the sweep below is what keeps it true: a handle that
// names an address the interface has given up hears nothing at all, which is the failure this leg cannot be
// allowed to have silently.
static string ReplyFilter(uint wanAddress) =>
    $"inbound and ip and ip.DstAddr == {NatTable.FormatAddress(wanAddress)} and " +
    $"(icmp or tcp.DstPort >= {NatTable.PortFirst} or udp.DstPort >= {NatTable.PortFirst}) and not impostor";
var replyFilter = ReplyFilter(wan.Addr);
WinDivertHandle reply;
try
{
    reply = new WinDivertHandle(replyFilter, Layer.Network, -50, Flag.None);
    replyHandle = reply;
}
catch (Exception ex)
{
    divert.Shutdown();
    Console.WriteLine($"[Router] WinDivertOpen failed for the reply leg: {ex.Message}");
    Console.WriteLine("[Router] Needs elevation - the driver is loaded on open.");
    return 1;
}

Console.WriteLine($"[Router] Reply leg: {replyFilter}");
Console.WriteLine("[Router] Layer.Network, priority -50. Disjoint from the proxy's outbound filter, so the two");
Console.WriteLine("[Router]   handles at this layer are never asked about the same packet.");

// The IPv6 half of the host's own inbound, which the filter above cannot see: `ip` is IPv4, and the bound
// below is an IPv4 clause. What this leg does is the rewrite and nothing else - no mapping is translated,
// because IPv6 has none here - so it is bounded to the resolver's port rather than to a WAN address and a
// mapped range. The server port is what names an answer, the same test DnsEch makes on the bytes.
// It costs one open handle whether or not this host resolves over IPv6: a filter this narrow is offered
// no traffic otherwise.
var v6ReplyFilter = "inbound and ipv6 and (udp.SrcPort == 53 or tcp.SrcPort == 53) and not impostor";
WinDivertHandle? v6Reply = null;
try
{
    v6Reply = new WinDivertHandle(v6ReplyFilter, Layer.Network, -50, Flag.None);
    v6ReplyHandle = v6Reply;
}
catch (Exception ex)
{
    Console.WriteLine($"[Router] the IPv6 reply leg did not open ({ex.Message}); this host's own IPv6 " +
                      "resolver answers keep their ech configuration");
}
if (v6Reply != null)
    Console.WriteLine($"[Router] IPv6 reply leg: {v6ReplyFilter}");

var v6ReplyReceived = 0L;
var v6ReplyNeutralised = 0L;
var v6ReplyPassthroughFailed = 0L;
unsafe void ReplyLoopV6(WinDivertHandle leg)
{
    var packetBuf = Marshal.AllocHGlobal(MTU_MAX);
    var addrBuf = Marshal.AllocHGlobal(ADDR_SIZE);
    var budget = 20;
    try
    {
        while (!cts.IsCancellationRequested)
        {
            int recvLen;
            if (!leg.Recv((void*)packetBuf, MTU_MAX, &recvLen, (Address*)addrBuf))
            {
                if (cts.IsCancellationRequested) break;
                continue;
            }

            var addr = (Address*)addrBuf;
            var packet = new Span<byte>((void*)packetBuf, recvLen);
            Interlocked.Increment(ref v6ReplyReceived);
            // This host's own IPv6 resolver traffic is local delivery, so this leg is the only place its
            // answers can be read - the DnsServer's own rewrite only covers what it serves to clients.
            var neutralised = DnsEch.TryNeutralize(packet);
            if (neutralised > 0)
            {
                Interlocked.Add(ref v6ReplyNeutralised, neutralised);
                if (budget-- > 0)
                    Console.WriteLine($"[Router] v6 {Host.Describe(packet)}: {neutralised} ech parameter(s) neutralised");
                leg.CalcChecksums((void*)packetBuf, recvLen, addr);
            }
            // Unchanged or rewritten, the packet is handed back with the address it arrived on and no
            // impostor flag, exactly as the v4 leg's passthrough branch does. A send that fails here loses
            // a packet of the host's, so it is counted rather than ignored.
            if (!leg.Send((void*)packetBuf, recvLen, null, addr))
                Interlocked.Increment(ref v6ReplyPassthroughFailed);
        }
    }
    catch (Exception ex)
    {
        // The same rule as the v4 leg: this handle queues the host's own inbound answers, so a loop that
        // has died silently is a blackout with no message.
        Console.WriteLine($"[Router] IPv6 reply leg failed: {ex.GetType().Name}: {ex.Message}");
        Abort();
    }
    finally
    {
        leg.Shutdown(ShutdownMode.Recv);
        // Printed here because a leg that saw nothing and a leg that saw answers with no ech parameter
        // otherwise end with the same silence - the arrival count is what says the handle was live.
        Console.WriteLine($"[Router] IPv6 reply leg: recv={Interlocked.Read(ref v6ReplyReceived)} " +
                          $"neutralised={Interlocked.Read(ref v6ReplyNeutralised)} " +
                          $"passthroughfail={Interlocked.Read(ref v6ReplyPassthroughFailed)}");
        Marshal.FreeHGlobal(packetBuf);
        Marshal.FreeHGlobal(addrBuf);
    }
}
if (v6Reply is { } v6ReplyLeg) _ = Task.Run(() => ReplyLoopV6(v6ReplyLeg), cts.Token);

var replyReceived = 0L;
var replyPassthroughFailed = 0L;
var replyRewriteFailed = 0L;
var replyV6Failed = 0L;
unsafe void ReplyLoop()
{
    var packetBuf = Marshal.AllocHGlobal(MTU_MAX);
    var addrBuf = Marshal.AllocHGlobal(ADDR_SIZE);
    var budget = 20;
    var leg = reply;
    try
    {
        while (!cts.IsCancellationRequested)
        {
            // The sweep puts a handle opened on the address the WAN has taken here and shuts the old one, so
            // the swap happens between packets rather than under one in flight - and this loop, not the
            // sweep, is the only thing that disposes a handle, because a Recv may still be on it.
            var current = Volatile.Read(ref reply);
            if (!ReferenceEquals(current, leg))
            {
                leg.Dispose();
                leg = current;
                replyHandle = leg;
                Console.WriteLine($"[Router] Reply leg re-opened: {ReplyFilter(table.WanAddress)}");
            }
            int recvLen;
            if (!leg.Recv((void*)packetBuf, MTU_MAX, &recvLen, (Address*)addrBuf))
            {
                if (cts.IsCancellationRequested) break;
                continue;
            }
            Interlocked.Increment(ref replyReceived);

            var addr = (Address*)addrBuf;
            var packet = new Span<byte>((void*)packetBuf, recvLen);
            // The host's own resolver answer is local delivery too, so this leg is the only place it can
            // be read; see DnsEch. Before Translate, because that is what writes the mapped source port
            // over the server port this decides on.
            var neutralised = DnsEch.TryNeutralize(packet);
            if (neutralised > 0 && budget-- > 0)
                Console.WriteLine($"[Router] {Host.Describe(packet)}: {neutralised} ech parameter(s) neutralised");
            var before = budget > 0 ? Host.Describe(packet) : null;
            // The two tables answer on one interface address, so the port that names a reply has exactly one
            // owner between them - which is what each allocator was shown the other's claims for. Asked here,
            // before the IPv4 NAT sees the packet, because its own reply branch finds no mapping for it and
            // would hand the answer to a stack with nothing listening on that port.
            Nat64Outcome? v6Answer = nat64 is { } stateful46 && stateful46.OwnsDatagram(packet)
                ? stateful46.Translate(packet, natPath)
                : null;
            if (v6Answer is Nat64Outcome a46)
            {
                if (a46.Action == Nat64Action.Translate)
                {
                    // Twenty octets longer than what arrived, the only direction here that grows a packet; the
                    // buffer was sized for 40 + 65535 because of it. Checksums first, because the IPv6 one
                    // covers the pseudo-header this rewrite changed, then the impostor flag for the same reason
                    // the branch below sets it: this copy is put back by a handle rather than arriving from the
                    // wire, and without the flag the forward-layer handle meets it on its way out to the client.
                    var out6 = a46.Packet!;
                    Marshal.Copy(out6, 0, packetBuf, out6.Length);
                    leg.CalcChecksums((void*)packetBuf, out6.Length, addr);
                    var after6 = Host.Describe(new Span<byte>((void*)packetBuf, out6.Length));
                    addr->Flags |= AddressFlag.Impostor;
                    var sent6 = leg.Send((void*)packetBuf, out6.Length, null, addr);
                    if (!sent6 && Interlocked.Increment(ref replyV6Failed) == 1)
                        Console.WriteLine($"[Router] NAT64 46 reinjection failed, error {Marshal.GetLastWin32Error()}");
                    if (budget-- > 0)
                        Console.WriteLine($"[Router] NAT64 46 {before} => {after6} " +
                                          $"ifIdx={addr->IfIdx} sent={sent6}");
                    continue;
                }
                if (a46.Action == Nat64Action.Discard)
                {
                    if (budget-- > 0)
                        Console.WriteLine($"[Router] NAT64 discarded: {a46.Reason} {Host.Describe(packet)}");
                    continue;
                }
                // None: the reverse key named a binding on the first read and not on the second, which is the
                // sweep running between them. Left for the IPv4 NAT below, which is what this leg does for
                // anything neither table claims.
            }
            // The arrival interface, which is what the network layer's address documents. Translate does
            // not read it for these packets: every one of them is addressed to the WAN side, so the reply
            // branch decides on the addresses alone.
            var outcome = table.Translate(packet, addr->IfIdx, wan.IfIdx);

            if (outcome.Action == NatAction.Discard)
            {
                // The packet is not put back, which is what RFC 5508 REQ-4 asks of an error that quotes no
                // flow of ours. Printed on the budget because an eaten PMTU notice is otherwise
                // indistinguishable from a path that never sent one.
                if (budget-- > 0)
                    Console.WriteLine($"[Router] ICMP error discarded: {outcome.Reason} {Host.Describe(packet)}");
                continue;
            }
            if (outcome.Action == NatAction.None)
            {
                // The host's own inbound traffic that happened to land in the mapped range: handed straight
                // back with the address it arrived on and no impostor flag, so the stack delivers it exactly
                // as it would have. A send that fails here loses a packet of the host's, which is why it is
                // counted rather than ignored. The checksums are redone only when the payload changed,
                // because an untouched datagram is handed back exactly as it arrived.
                if (neutralised > 0) leg.CalcChecksums((void*)packetBuf, recvLen, addr);
                if (!leg.Send((void*)packetBuf, recvLen, null, addr))
                    Interlocked.Increment(ref replyPassthroughFailed);
                continue;
            }

            leg.CalcChecksums((void*)packetBuf, recvLen, addr);
            // Marked impostor because it is one: this copy is being put back by a handle rather than
            // arriving from the wire, and the flag is what stops the forward-layer handle below from taking
            // it again on its way out to the client. WinDivert decrements the TTL for an impostor injection,
            // which is what a router owes the packet anyway.
            addr->Flags |= AddressFlag.Impostor;
            var sent = leg.Send((void*)packetBuf, recvLen, null, addr);
            if (!sent) Interlocked.Increment(ref replyRewriteFailed);
            if (budget-- > 0)
                Console.WriteLine($"[Router] {outcome.Action} {before} => {Host.Describe(packet)} " +
                                  $"ifIdx={addr->IfIdx} sent={sent}");
        }
    }
    catch (Exception ex)
    {
        // A faulted leg is worse than a stopped one: this handle captures the host's own inbound traffic
        // in the mapped port range as well, so a loop that has died silently is a blackout with no
        // message. Tear the run down instead of leaving it half-alive.
        Console.WriteLine($"[Router] reply leg failed: {ex.GetType().Name}: {ex.Message}");
        Abort();
    }
    finally
    {
        leg.Shutdown(ShutdownMode.Recv);
        Marshal.FreeHGlobal(packetBuf);
        Marshal.FreeHGlobal(addrBuf);
    }
}

_ = Task.Run(ReplyLoop, cts.Token);

using (divert)
{
    var logBudget = 40;
    // A diverted packet has already left the stack, so a reinjection that fails does not fall back to
    // anything - the packet is simply gone and the sender retransmits into the same hole. Both call
    // sites count their failures instead of discarding the return value, because "no counter moved" is
    // otherwise read as "no packet arrived" when it means "the packet was eaten here".
    var passthroughFailed = 0;
    var rewriteFailed = 0;
    // The same two failures on the IPv6 leg of --nat64, kept apart from the pair above because they say
    // different things: these ones cost a dual-stack flow that nothing here was supposed to touch, so a
    // run that shows them non-zero is a run where the widened filter disturbed the plain v6 path.
    var v6PassthroughFailed = 0;
    var v6RewriteFailed = 0;
    // Counted separately from every decision below it: with only the action counters, "the filter took
    // nothing" and "the decision tree declined everything" print the same line.
    var received = 0;
    var packetBuf = Marshal.AllocHGlobal(MTU_MAX);
    var addrBuf = Marshal.AllocHGlobal(ADDR_SIZE);
    // WinDivertRecv writes the length through this pointer while the call is in flight, and a native call
    // does not pin what it points at. A local of an async method is a field of the state-machine object on
    // the heap - which is what CS9123 is about - so the length gets the same unmanaged slot as the two
    // buffers above instead of `&recvLen`.
    var lenBuf = Marshal.AllocHGlobal(sizeof(int));
    unsafe
    {
        new Span<byte>((void*)packetBuf, MTU_MAX).Clear();
        new Span<byte>((void*)addrBuf, ADDR_SIZE).Clear();
    }

    _ = Task.Run(async () =>
    {
        var noAddressReported = false;
        var reopenFailedFor = 0u;
        while (!cts.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromSeconds(5), cts.Token).ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
            table.Sweep();
            // Its own sweep on the same clock. RFC 6146 §4.4's TCP timers run to 124 minutes, so a table that
            // is only swept when the IPv4 one happens to need it would hold a binding - and the port under it -
            // for longer than the specification lets it.
            nat64?.Sweep();

            // The other half of these five seconds. A WAN that renews its lease changes both what a SNAT
            // writes and what the reply leg's filter names, and a source the interface no longer owns is a
            // packet the upstream drops as spoofed. Keyed on the interface index rather than re-picking a
            // WAN side, because the choice at startup was this interface's and only its address moved.
            InterfaceInfo? current = null;
            try
            {
                current = Host.DiscoverIpv4().FirstOrDefault(c => c.IfIdx == wan.IfIdx);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Router] WAN address re-read failed: {ex.GetType().Name}: {ex.Message}");
            }

            if (current is null)
            {
                if (!noAddressReported)
                {
                    noAddressReported = true;
                    Console.WriteLine($"[Router] WAN ifIdx={wan.IfIdx} has no IPv4 address right now; keeping " +
                                      $"{NatTable.FormatAddress(table.WanAddress)} as the source until one is back.");
                }
                continue;
            }
            noAddressReported = false;
            if (current.Addr == table.WanAddress || current.Addr == reopenFailedFor) continue;

            WinDivertHandle opened;
            try
            {
                opened = new WinDivertHandle(ReplyFilter(current.Addr), Layer.Network, -50, Flag.None);
            }
            catch (Exception ex)
            {
                // One attempt per address: this is the driver refusing, which the next five seconds would
                // report in the same words. Nothing moves, so the table and the filter keep agreeing about
                // one address instead of each holding a different one.
                reopenFailedFor = current.Addr;
                Console.WriteLine($"[Router] WAN ifIdx={wan.IfIdx} now answers {NatTable.FormatAddress(current.Addr)}" +
                                  $" but the reply leg could not be re-opened on it: {ex.GetType().Name}: {ex.Message}." +
                                  " A flow through this program stays broken until the leg comes back.");
                continue;
            }

            // The table first: a reply that arrives while the old handle is still shutting down is read
            // against the address it came to, so the new filter must never be the only half that moved.
            var previous = table.WanAddress;
            table.SetWanAddress(current.Addr);
            // The same source follows on the other table: §5.2's mapping is endpoint-independent, so nothing
            // keyed on the address moves, but the next packet of every live flow is written with the new one -
            // and OwnsDatagram's test that a reply came to this table's address is read against it too.
            nat64?.SetWanAddress(System.Net.IPAddress.Parse(NatTable.FormatAddress(current.Addr)));
            var old = Interlocked.Exchange(ref reply, opened);
            old.Shutdown(ShutdownMode.Recv);
            Console.WriteLine($"[Router] WAN address {NatTable.FormatAddress(previous)} -> " +
                              $"{NatTable.FormatAddress(current.Addr)} (the interface renewed): the source follows it, " +
                              "and the reply leg is re-opened on the new filter");
        }
    });
    _ = Task.Run(async () =>
    {
        while (!cts.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromSeconds(statsSeconds), cts.Token).ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
            // The pair is what tells a client's fragmented flow apart from a stalled one: fragmap counts the
            // fragments rewritten from their datagram's first one, frag counts those forwarded as they
            // arrived because no first fragment of theirs came this way.
            Console.WriteLine($"[Router] recv={received} snat={table.Snats} dnat={table.Dnats} flows={table.FlowCount} " +
                              $"local={table.LocalDest} wrongif={table.WrongIf} frag={table.Fragments} " +
                              $"fragmap={table.FragmentRewrites} " +
                              $"otherproto={table.UnmappedProtocol} icmperr={table.IcmpErrors} " +
                              $"icmpdrop={table.IcmpErrorsDropped} passthroughfail={passthroughFailed} " +
                              $"rewritefail={rewriteFailed} heldskip={table.PortHeld}" +
                              // v6passthroughfail is the one that matters for the plain path: it counts a dual-stack
                              // flow this program took and could not put back, so a run with --nat64 that leaves it
                              // at zero is a run where widening the filter cost the IPv6 route nothing.
                              (nat64 is null ? "" :
                                  $" v6passthroughfail={v6PassthroughFailed} v6rewritefail={v6RewriteFailed} " +
                                  $"nat64 out={nat64.Translated64} in={nat64.Translated46} bib={nat64.BindingCount} " +
                                  $"ste={nat64.SessionCount} frag={nat64.FragmentRecordCount} " +
                                  $"hair={nat64.Hairpins} nohit={nat64.NoBinding} filt={nat64.Filtered} " +
                                  $"exh={nat64.Exhausted} fragreuse={nat64.FragmentReuses} fragno={nat64.FragmentRefused}"));
            // On its own line because dnat can only come from this leg now: a packet addressed to this
            // host's WAN address is local delivery, so the forward handle is never offered one.
            Console.WriteLine($"[Router] reply recv={replyReceived} passthroughfail={replyPassthroughFailed} " +
                              $"rewritefail={replyRewriteFailed}" +
                              (nat64 is null ? "" : $" nat64fail={replyV6Failed}"));
        }
    });

    // One thread for the PD client and the advertisements, started where nothing below can return early
    // without reaching the shutdown below.
    Task? v6Task = v6 is { } v6Router ? Task.Run(() => v6Router.Run(cts.Token)) : null;

    try
    {
        unsafe
        {
            while (!cts.IsCancellationRequested)
            {
                if (!divert.Recv((void*)packetBuf, MTU_MAX, (int*)lenBuf, (Address*)addrBuf))
                {
                    if (cts.IsCancellationRequested) break;
                    continue;
                }
                var recvLen = *(int*)lenBuf;
                received++;

                var addr = (Address*)addrBuf;
                var packet = new Span<byte>((void*)packetBuf, recvLen);
                // IPv6 reaches this line only with --nat64, which is what widened the filter above to ask
                // about it: the stateful PLAT decides per packet, and a v6 datagram aimed at an address
                // inside the Pref64::/n is a client asking for an IPv4-only server. Everything the table
                // does not take goes back untouched for Windows' own forwarding, which is the path this run
                // must leave undisturbed. The version test is also what keeps DnsEch off these bytes: it
                // reads the IPv4 header's length field, and a v6 traffic class would be read as one.
                if (nat64 is { } stateful && recvLen >= 40 && packet[0] >> 4 == 6)
                {
                    var v6Before = logBudget > 0 ? Host.Describe(packet) : null;
                    var sixToFour = stateful.Translate(packet, natPath);
                    if (sixToFour.Action == Nat64Action.Discard)
                    {
                        // Not put back, the same reading of RFC 5508 REQ-4 the IPv4 branch below works from:
                        // §3.5's filters and §3.4's gates say the packet is dropped, and a drop that prints
                        // nothing is indistinguishable from a client that never sent it.
                        if (logBudget-- > 0)
                            Console.WriteLine($"[Router] NAT64 discarded: {sixToFour.Reason} {Host.Describe(packet)}");
                        continue;
                    }
                    if (sixToFour.Action == Nat64Action.None)
                    {
                        // Untouched, so no checksum work and no impostor flag: the stack sees what it would
                        // have seen without this program. Counted on its own because the flow this loses is a
                        // dual-stack one, and a shared counter would read as a broken IPv4 passthrough.
                        if (!divert.Send((void*)packetBuf, recvLen, null, addr))
                        {
                            if (++v6PassthroughFailed == 1)
                                Console.WriteLine($"[Router] NAT64 passthrough reinjection failed, error {Marshal.GetLastWin32Error()}: {Host.Describe(packet)}");
                        }
                        continue;
                    }
                    // Usually twenty octets shorter than what arrived: the 40-octet fixed header and any
                    // extension headers the SIIT walk stepped over become a 20-octet IPv4 one. Not always - a
                    // hairpin (§3.8, a client addressing another client's mapped port through the prefix) is
                    // translated twice inside one call and comes back IPv6 - so the length written into the
                    // driver's buffer is the translated one and never recvLen, and the bytes past it are stale.
                    var out64 = sixToFour.Packet!;
                    Marshal.Copy(out64, 0, packetBuf, out64.Length);
                    divert.CalcChecksums((void*)packetBuf, out64.Length, addr);
                    var v6After = Host.Describe(new Span<byte>((void*)packetBuf, out64.Length));
                    var v6Sent = divert.Send((void*)packetBuf, out64.Length, null, addr);
                    if (!v6Sent && ++v6RewriteFailed == 1)
                        Console.WriteLine($"[Router] NAT64 64 reinjection failed, error {Marshal.GetLastWin32Error()}");
                    if (logBudget-- > 0)
                        Console.WriteLine($"[Router] NAT64 64 {v6Before} => {v6After} ifIdx={addr->IfIdx} sent={v6Sent}");
                    continue;
                }
                // A client's own resolver answer, or one that bypasses this host's resolver, is transport
                // here; the server port is what names it, so the rewrite runs before Translate writes the
                // mapped one over it. See DnsEch.
                var neutralised = DnsEch.TryNeutralize(packet);
                if (neutralised > 0 && logBudget > 0)
                    Console.WriteLine($"[Router] {Host.Describe(packet)}: {neutralised} ech parameter(s) neutralised");
                // Taken before Translate, which rewrites in place: captured afterwards both halves of the
                // log line print the same packet and the line proves nothing about what changed. Only while
                // the budget lasts, so the per-packet string is not paid for after the diagnostic window.
                var before = logBudget > 0 ? Host.Describe(packet) : null;
                var outcome = table.Translate(packet, addr->IfIdx, wan.IfIdx);

                if (outcome.Action == NatAction.Discard)
                {
                    // Not put back, which is what RFC 5508 REQ-4 asks of an error that quotes no flow of
                    // ours; printed on the budget because an eaten PMTU notice otherwise looks exactly
                    // like a path that never sent one.
                    if (logBudget-- > 0)
                        Console.WriteLine($"[Router] ICMP error discarded: {outcome.Reason} {Host.Describe(packet)}");
                    continue;
                }
                if (outcome.Action == NatAction.None)
                {
                    // Upstream's own note is that an application which never modifies a packet should sniff
                    // instead of divert-and-reinject, and warns that unmodified reinjections can loop between
                    // WFP callout drivers until the send fails ERROR_HOST_UNREACHABLE (1232). This handle
                    // cannot sniff, because a rewrite is decided per packet, so the loop guard is the filter's
                    // impostor condition and 1232 on this counter is what its failure looks like. The
                    // checksums are redone only when the payload changed: an untouched packet is handed back
                    // exactly as it arrived.
                    if (neutralised > 0) divert.CalcChecksums((void*)packetBuf, recvLen, addr);
                    if (!divert.Send((void*)packetBuf, recvLen, null, addr))
                    {
                        if (++passthroughFailed == 1)
                            Console.WriteLine($"[Router] passthrough reinjection failed, error {Marshal.GetLastWin32Error()}: {Host.Describe(packet)}");
                    }
                    continue;
                }

                // Reinjected with the address it arrived with. Nothing here tries to steer the egress by
                // rewriting the index: upstream describes Network.IfIdx as the interface an inbound packet
                // arrived on or an outbound one is to be sent on, and in the same section says the value is
                // ignored for outbound packets, so the only defensible use is to hand back what we were
                // given. The checksums are recalculated because the rewrite invalidates them, and an
                // injected packet has to carry correct ones or have the matching flag cleared.
                var after = Host.Describe(packet);
                divert.CalcChecksums((void*)packetBuf, recvLen, addr);
                var sent = divert.Send((void*)packetBuf, recvLen, null, addr);
                // Upstream lists injecting certain inbound ICMP messages as a call that fails by design, so
                // a failure printed here on an ICMP flow is not by itself evidence about the NAT.
                if (!sent && ++rewriteFailed == 1)
                    Console.WriteLine($"[Router] {outcome.Action} reinjection failed, error {Marshal.GetLastWin32Error()}");
                if (logBudget-- > 0)
                    Console.WriteLine($"[Router] {outcome.Action} {before} => {after} ifIdx={addr->IfIdx} sent={sent}");
            }
        }
    }
    catch (OperationCanceledException)
    {
    }
    finally
    {
        divert.Shutdown();
        reply.Shutdown(ShutdownMode.Recv);
        reply.Dispose();
        Marshal.FreeHGlobal(packetBuf);
        Marshal.FreeHGlobal(addrBuf);
        Marshal.FreeHGlobal(lenBuf);
        sniffer?.Dispose();
        netSniffer?.Dispose();
        v6Sniffer?.Dispose();
        v6NetSniffer?.Dispose();
        dhcpSocket?.Dispose();
        dnsSocket?.Dispose();
        dnsTcp?.Stop();
        upstreamSocket?.Dispose();
        // Before the summary line, so "stopped" is only printed once the Release has gone out and the LAN
        // address the delegation installed has been taken back. Cancelling here rather than relying on the
        // interrupt handler covers every other way this block can end.
        cts.Cancel();
        v6Task?.Wait(TimeSpan.FromSeconds(10));
    }
}

ReleaseLanRules(quiet: false);

Console.WriteLine($"[Router] Stopped. snat={table.Snats} dnat={table.Dnats}");
return 0;

// Each name is only this program's to take back if this run put it in, which is what the two flags record:
// a rule the operator made by hand is left alone. The exchange makes it one release per process, because the
// close signal runs this on its own thread while Main may still be on its way to its own call.
void ReleaseLanRules(bool quiet)
{
    if (Interlocked.Exchange(ref lanRulesReleased, 1) != 0) return;
    if (lanRuleOwned)
    {
        InboundFirewall.Remove(LanRuleName);
        lanRuleOwned = false;
        if (!quiet) Console.WriteLine($"[Router] '{LanRuleName}' removed again");
    }
    if (dnsTcpRuleOwned)
    {
        InboundFirewall.Remove(DnsTcpRuleName);
        dnsTcpRuleOwned = false;
        if (!quiet) Console.WriteLine($"[Router] '{DnsTcpRuleName}' removed again");
    }
}

sealed class TimestampWriter : TextWriter
{
    private readonly TextWriter _inner;

    public TimestampWriter(TextWriter inner) => _inner = inner;

    public override Encoding Encoding => _inner.Encoding;

    public override void Write(char value) => _inner.Write(value);
    public override void Write(string? value) => _inner.Write(value);
    public override void WriteLine(string? value) => _inner.WriteLine($"{DateTime.Now:HH:mm:ss.fff} {value}");
    public override void WriteLine() => _inner.WriteLine();
    public override void Flush() => _inner.Flush();
}
