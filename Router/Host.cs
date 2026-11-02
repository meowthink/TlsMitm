using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Numerics;
using System.Runtime.InteropServices;
using static TlsMitm.WinDivertPInvoke;

namespace Router;

public sealed record InterfaceInfo(string Name, int IfIdx, uint Addr, uint Mask, uint Gateway, string Media)
{
    public string AddrText => NatTable.FormatAddress(Addr);
    public string GatewayText => Gateway == 0 ? "none" : NatTable.FormatAddress(Gateway);
    public int Prefix => BitOperations.PopCount(Mask);
}

public static class Host
{
    // A value is the next token only when that token is not another option. Two options have a bare form
    // whose value is optional -- --pref64 falling back to RFC 6147 §5.2's well-known prefix, --trace to a
    // line count -- so in "--pref64 --nat64" the second token means the flag, and reading it as a prefix
    // turns a valid command line into a refusal to parse an address called "--nat64".
    public static string? OptionValue(string[] args, string name)
    {
        var index = Array.IndexOf(args, name);
        return index >= 0 && index + 1 < args.Length && !args[index + 1].StartsWith("--")
            ? args[index + 1]
            : null;
    }

    // For the options that are given more than once, one value per thing configured.
    public static List<string> OptionValues(string[] args, string name)
    {
        var found = new List<string>();
        for (var i = 0; i + 1 < args.Length; i++)
            if (args[i] == name && !args[i + 1].StartsWith("--")) found.Add(args[i + 1]);
        return found;
    }

    public static List<InterfaceInfo> DiscoverIpv4()
    {
        var found = new List<InterfaceInfo>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

            var properties = nic.GetIPProperties();
            uint addr = 0, mask = 0;
            foreach (var unicast in properties.UnicastAddresses)
            {
                if (unicast.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                if (IsLinkLocal(unicast.Address)) continue;
                addr = ToBigEndian(unicast.Address);
                mask = unicast.IPv4Mask is null ? 0xFFFFFFFFu : ToBigEndian(unicast.IPv4Mask);
                break;
            }
            if (addr == 0) continue;

            uint gateway = 0;
            foreach (var gatewayAddress in properties.GatewayAddresses)
            {
                if (gatewayAddress.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                if (gatewayAddress.Address.Equals(IPAddress.Any)) continue;
                gateway = ToBigEndian(gatewayAddress.Address);
                break;
            }

            var ifIdx = ResolveIfIndex(addr);
            if (ifIdx <= 0) continue;
            found.Add(new InterfaceInfo(nic.Name, ifIdx, addr, mask, gateway, nic.NetworkInterfaceType.ToString()));
        }
        return found;
    }

    // GetBestInterfaceEx is asked for the route to one of this host's own addresses, which is the
    // interface that owns it. SockAddr.V4Addr is sin_addr.s_addr, the octets in wire order read
    // little-endian, so the readable form this program keeps has to be byte-swapped for the call.
    public static int ResolveIfIndex(uint bigEndianAddr)
    {
        var sockaddr = SockAddr.FromIPv4(BinaryPrimitives.ReverseEndianness(bigEndianAddr));
        return GetBestInterfaceEx(ref sockaddr, out var ifIdx) == 0 ? ifIdx : 0;
    }

    // Read and written through the OS's own view rather than through MIB_IPINTERFACE_ROW: that
    // struct's field offsets are not worth the risk of reading one byte over, and this runs twice at
    // startup.
    public static string? QueryForwarding(int ifIdx, string family = "IPv4")
    {
        var output = RunPowerShell($"(Get-NetIPInterface -InterfaceIndex {ifIdx} -AddressFamily {family}).Forwarding");
        return output?.Trim() is { Length: > 0 } value ? value : null;
    }

    // The resolver this host already uses, asked of the same per-interface configuration Windows keeps
    // for it. Used as the default upstream so the LAN side resolves through what the host itself
    // resolves through; --dns overrides it.
    public static uint? QueryDnsServer(int ifIdx)
    {
        var output = RunPowerShell(
            $"(Get-DnsClientServerAddress -InterfaceIndex {ifIdx} -AddressFamily IPv4).ServerAddresses");
        if (output is null) return null;
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            if (TryParseDotted(line.Trim(), out var address))
                return address;
        return null;
    }

    private static bool TryParseDotted(string text, out uint address)
    {
        address = 0;
        try { address = NatTable.ParseAddress(text); }
        catch (Exception ex) when (ex is FormatException or OverflowException) { return false; }
        return true;
    }

    public static void SetForwarding(int ifIdx, string family = "IPv4")
    {
        // Same reason `StopService` reads the error stream now: this call fails in a shell that is not
        // elevated, and a stdout-only runner printed "done" over it. The state is re-queried by the caller
        // either way, but the refusal's own words belong on the record.
        var output = RunPowerShell(
            $"Set-NetIPInterface -InterfaceIndex {ifIdx} -AddressFamily {family} -Forwarding Enabled -ErrorAction Stop",
            withStdErr: true);
        Console.WriteLine(output is { Length: > 0 }
            ? $"[Router] Set-NetIPInterface {ifIdx} {family}: {output.Trim()}"
            : $"[Router] Set-NetIPInterface {ifIdx} {family}: done");
    }

    // The adapter itself, so the v6 side can read what only it knows. Matched by name because the name is
    // what the LAN/WAN pick already carries, and an adapter that is down still reports both addresses.
    public static NetworkInterface? FindInterface(string name)
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            if (nic.Name == name) return nic;
        return null;
    }

    // RFC 4861 §4.2 requires a Router Advertisement's source to be "the link-local address assigned to the
    // interface from which this message is sent", and RFC 8415 §7.2 binds the client's socket to the
    // link-local of the interface its server is reached on. The kernel's own table answers this rather than
    // the adapter, together with the state it gives the address: an interface can hold an old link-local
    // beside the live one - the address is derived from the hardware address, so it changes when that does -
    // and the RA checksum covers the source written into the packet, so naming the one the kernel will not
    // send from would hand every host on the link a message it must discard. A Deprecated one is still
    // returned when it is the only one there, because that is what the kernel sends from too.
    public static (IPAddress Address, string State)? LinkLocal(int ifIdx)
    {
        var output = RunPowerShell(
            $"Get-NetIPAddress -InterfaceIndex {ifIdx} -AddressFamily IPv6 " +
            "| Where-Object { $_.IPAddress -like 'fe80*' } " +
            "| ForEach-Object { \"$($_.IPAddress) $($_.AddressState)\" }");
        if (output is null) return null;
        (IPAddress Address, string State)? any = null;
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var text = line.Trim();
            var space = text.LastIndexOf(' ');
            if (space <= 0) continue;
            var state = text[(space + 1)..].Trim();
            var address = text[..space].Trim();
            // The zone in the printed form names the interface we just queried by index, so it is dropped
            // and left for the caller to re-attach - a string read off a shell is not the authority on it.
            var zone = address.IndexOf('%');
            if (zone >= 0) address = address[..zone];
            if (!IPAddress.TryParse(address, out var parsed) || !parsed.IsIPv6LinkLocal) continue;
            if (state.Equals("Preferred", StringComparison.OrdinalIgnoreCase)) return (parsed, state);
            any ??= (parsed, state);
        }
        return any;
    }

    // Whether Windows will put its own Router Advertisements on this interface. netsh's `show interface` is
    // the only surface that reports it - Get-NetIPInterface has no such property, measured 2026-10-31 on
    // this host - and the value matters because a second advertiser on the LAN advertises the prefix this
    // program installed without its resolver option, which makes a live run's RAs unattributable.
    public static string? QueryRaAdvertiser(int ifIdx)
    {
        var output = RunPowerShell($"netsh interface ipv6 show interface {ifIdx}");
        if (output is null) return null;
        foreach (var line in output.Split('\n'))
        {
            var trimmed = line.Trim();
            if (!trimmed.StartsWith("Advertising", StringComparison.Ordinal)) continue;
            var colon = trimmed.IndexOf(':');
            return colon < 0 ? null : trimmed[(colon + 1)..].Trim();
        }
        return null;
    }

    // What RFC 4861 §4.6.1's Source Link-Layer Address option carries. Six octets is an Ethernet address,
    // which is the only shape this LAN side has.
    public static byte[]? MacAddress(string nicName)
        => FindInterface(nicName)?.GetPhysicalAddress().GetAddressBytes() is { Length: 6 } mac ? mac : null;

    // The largest IPv6 packet the link carries whole. The advertisement repeats it so a LAN host stops
    // above it instead of handing this host something it would have to fragment.
    public static uint? QueryMtu(int ifIdx, string family = "IPv6")
    {
        var output = RunPowerShell($"(Get-NetIPInterface -InterfaceIndex {ifIdx} -AddressFamily {family}).NlMtu");
        return uint.TryParse(output?.Trim(), out var mtu) && mtu > 0 ? mtu : null;
    }

    // The LAN's own address inside the delegated prefix. The prefix length is the point: it installs the
    // on-link route for the whole /64, which is what makes a client's address reachable through this
    // interface at all. A run that crashed leaves the same address behind, and that is the state this run
    // wants, so an add that finds it there is reported and counted as done.
    public static bool AddIpv6Address(IPAddress address, int prefixLength, int ifIdx)
    {
        var (code, output) = RunPowerShellExit(
            $"New-NetIPAddress -InterfaceIndex {ifIdx} -IPAddress {address} -PrefixLength {prefixLength} " +
            "-AddressFamily IPv6 -ErrorAction Stop | Out-Null", withStdErr: true);
        if (code == 0) return true;
        if (output?.Contains("already exists", StringComparison.OrdinalIgnoreCase) == true)
        {
            Console.WriteLine($"[Router] {address}/{prefixLength} is already on ifIdx {ifIdx}; left in place");
            return true;
        }
        Console.WriteLine($"[Router] New-NetIPAddress {address}/{prefixLength} on ifIdx {ifIdx} failed: " +
                          $"{output?.Trim()}");
        return false;
    }

    // RFC 4862 §5.4: an address under Duplicate Address Detection "is said to be tentative until the
    // procedure has completed successfully", and until then it is not to be assigned to an interface, which
    // is what a socket bind on it answers with. Measured on this host's Ethernet on 2026-11-01: putting the
    // resolver's port on the delegated address two milliseconds after New-NetIPAddress returned failed with
    // WSAEADDRNOTAVAIL, "The requested address is not valid in its context", and the advertisement went out
    // naming the delegation's resolver instead. §5.4's tentative state is the reading of that failure this
    // wait tests: it prints the state it found, so the next run either confirms it or names another clue.
    // §5.1's own clock is DupAddrDetectTransmits (default 1) times RetransTimer (default 1000 msec), so
    // the budget the caller passes is ours rather than the RFC's. A Deprecated address counts as usable:
    // §5.4's bar is about the tentative state, and both a Preferred ULA and this interface's Deprecated
    // link-local took a UDP bind when they were tried on 2026-11-01.
    public static (string? State, bool Waited) WaitUsableAddress(IPAddress address, int ifIdx, TimeSpan budget)
    {
        var deadline = DateTime.UtcNow + budget;
        var state = QueryAddressState(address, ifIdx);
        var waited = false;
        while (!IsUsable(state) && string.Equals(state, "Tentative", StringComparison.OrdinalIgnoreCase)
               && DateTime.UtcNow < deadline)
        {
            waited = true;
            Thread.Sleep(TimeSpan.FromSeconds(1));
            state = QueryAddressState(address, ifIdx);
        }

        return (state, waited);
    }

    public static bool IsUsable(string? state) =>
        state is "Preferred" or "Deprecated";

    private static string? QueryAddressState(IPAddress address, int ifIdx)
    {
        var output = RunPowerShell(
            $"(Get-NetIPAddress -InterfaceIndex {ifIdx} -AddressFamily IPv6 -IPAddress {address} " +
            "-ErrorAction SilentlyContinue).AddressState");
        // No match prints nothing at all, which is the same text as a cmdlet that could not run; neither
        // is a state, and the caller has to be able to tell "not there yet" from "Preferred".
        return output?.Trim() is { Length: > 0 } value ? value : null;
    }

    public static void RemoveIpv6Address(IPAddress address, int ifIdx)
    {
        var (code, output) = RunPowerShellExit(
            $"Remove-NetIPAddress -InterfaceIndex {ifIdx} -IPAddress {address} -AddressFamily IPv6 " +
            "-Confirm:$false -ErrorAction Stop | Out-Null", withStdErr: true);
        Console.WriteLine(code == 0
            ? $"[Router] removed {address} from ifIdx {ifIdx}"
            : $"[Router] Remove-NetIPAddress {address} on ifIdx {ifIdx} failed: {output?.Trim()}");
    }

    // Whether the interface still carries this IPv4 address. Asked of the kernel rather than remembered from
    // the startup listing, because that listing can describe a state that stops being true mid-startup:
    // measured 2026-11-02, stopping SharedAccess took 192.168.137.1 off the Wi-Fi Direct adapter that had
    // been showing it as the LAN, and the three sockets this program then opened on that address answered
    // WSAEADDRNOTAVAIL, "The requested address is not valid in its context" - a client associated, asked for
    // a lease, and never got one.
    public static bool HasIpv4Address(int ifIdx, string address)
    {
        var output = RunPowerShell(
            $"(Get-NetIPAddress -InterfaceIndex {ifIdx} -AddressFamily IPv4 -IPAddress {address} " +
            "-ErrorAction SilentlyContinue).IPAddress");
        return string.Equals(output?.Trim(), address, StringComparison.OrdinalIgnoreCase);
    }

    // The add, for that case. `-ErrorAction Stop` beside the "already exists" reading is the same pair
    // AddIpv6Address uses: an address a previous run left behind is the state this run wants, and a cmdlet
    // that reports failure can still have written the store entry, which is how 192.168.122.1 came to be
    // configured on an interface nobody named.
    public static bool AddIpv4Address(string address, int prefixLength, int ifIdx)
    {
        var (code, output) = RunPowerShellExit(
            $"New-NetIPAddress -InterfaceIndex {ifIdx} -IPAddress {address} -PrefixLength {prefixLength} " +
            "-AddressFamily IPv4 -ErrorAction Stop | Out-Null", withStdErr: true);
        if (code == 0) return true;
        if (output?.Contains("already exists", StringComparison.OrdinalIgnoreCase) == true)
        {
            Console.WriteLine($"[Router] {address}/{prefixLength} is already on ifIdx {ifIdx}; left in place");
            return true;
        }
        Console.WriteLine($"[Router] New-NetIPAddress {address}/{prefixLength} on ifIdx {ifIdx} failed: " +
                          $"{output?.Trim()}");
        return false;
    }

    // Internet Connection Sharing is Windows' own NAT, and the driver's documentation says the forward
    // layer is not to be mixed with it: both would rewrite the same transit packet, and which one wins
    // is not something this program can observe afterwards. Its service state is the signal - measured
    // here with sharing off, SharedAccess sits Stopped while winnat is Running and Automatic, so the
    // NAT driver being loaded says nothing and only the service says whether sharing is active.
    public static string? QueryServiceState(string name)
    {
        var output = RunPowerShell($"(Get-Service -Name {name} -ErrorAction SilentlyContinue).Status");
        return output?.Trim() is { Length: > 0 } value ? value : null;
    }

    // The state the service is in when this returns, not whether the stop was asked for: measured live on
    // 2026-10-31, `Stop-Service SharedAccess` printed nothing, this program reported "done", and the very
    // next query said Running. The cmdlet's reason had gone to a stream nobody read.
    public static string? StopService(string name)
    {
        var output = RunPowerShell($"Stop-Service -Name {name} -ErrorAction Stop", withStdErr: true);
        Console.WriteLine(output is { Length: > 0 }
            ? $"[Router] Stop-Service {name}: {output.Trim()}"
            : $"[Router] Stop-Service {name}: accepted");

        // A service that accepted the stop can still be a second away from it, and `Running` read in that
        // window would refuse a run that was about to be safe.
        string? state;
        for (var attempt = 0; attempt < 10; attempt++)
        {
            state = QueryServiceState(name);
            if (state is not ("Running" or "StopPending")) return state;
            Thread.Sleep(1000);
        }
        return QueryServiceState(name);
    }

    public static string? RunPowerShell(string script, bool withStdErr = false)
        => RunPowerShellExit(script, withStdErr).Output;

    // The code as well as the text, because an address add is judged by whether it happened: a cmdlet
    // that writes an error record and exits zero would otherwise look the same as one that worked.
    public static (int Code, string? Output) RunPowerShellExit(string script, bool withStdErr = false)
    {
        try
        {
            var start = new ProcessStartInfo("powershell.exe")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            start.ArgumentList.Add("-NoProfile");
            start.ArgumentList.Add("-Command");
            start.ArgumentList.Add(script);
            using var process = Process.Start(start);
            if (process is null) return (-1, null);
            // A cmdlet writes its error records to stderr, where a caller that only reads stdout cannot see
            // them. Drained concurrently because a child that fills the error buffer blocks there, and the
            // stdout read above would then never return.
            var errorRead = process.StandardError.ReadToEndAsync();
            var stdout = process.StandardOutput.ReadToEnd();
            if (!process.WaitForExit(15000)) return (-1, null);
            var stderr = errorRead.Wait(2000) ? errorRead.Result : "";
            return (process.ExitCode, withStdErr && stderr.Trim().Length > 0
                ? stdout.Trim() + "\n" + stderr.Trim()
                : stdout);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Router] PowerShell query failed: {ex.Message}");
            return (-1, null);
        }
    }

    public static string Describe(ReadOnlySpan<byte> packet)
    {
        if (packet.Length > 0 && (packet[0] >> 4) == 6) return DescribeV6(packet);
        if (packet.Length < 20 || (packet[0] >> 4) != 4) return "non-ipv4";
        var ihl = (packet[0] & 0x0F) * 4;
        if (packet.Length < ihl) return "truncated-ipv4";
        var proto = packet[9];
        var src = NatTable.FormatAddress(BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(12, 4)));
        var dst = NatTable.FormatAddress(BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(16, 4)));
        var name = proto switch { 1 => "icmp", 6 => "tcp", 17 => "udp", _ => $"proto{proto}" };
        if (proto is not (6 or 17) || packet.Length < ihl + 4)
            return $"{name} {src} -> {dst}";
        var sport = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ihl, 2));
        var dport = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ihl + 2, 2));
        return $"{name} {src}:{sport} -> {dst}:{dport}";
    }

    // RFC 8200 §3 fixes this header's field order: version/traffic-class/flow-label, payload length, next
    // header, hop limit, then the two addresses - so the next header is at index 6 and the transport is at
    // the end of whatever §4.1's chain of headers follows it. That is the walk TlsMitm/Ipv6Chain.cs, the one
    // the redirector swaps by and the reply leg rewrites by, so the trace names the same octets they act
    // on: the first header stepped over and the transport it leads to, with the transport's own ports.
    private static string DescribeV6(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 40) return "truncated-ipv6";
        var next = packet[6];
        var src = V6Address(packet.Slice(8, 16));
        var dst = V6Address(packet.Slice(24, 16));
        var name = next switch
        {
            6 => "tcp", 17 => "udp", 58 => "icmpv6",
            0 => "hopbyhop", 43 => "routing", 44 => "fragment", 60 => "destination",
            _ => $"nh{next}",
        };
        // The two ICMPv6 messages that decide whether a v6 path can work: a Neighbour Solicitation or its
        // Advertisement names the address being resolved (RFC 4861 §4.3, §4.4), and a Packet Too Big carries
        // the MTU the sender has to fall back to (RFC 4443 §3.2) - which is the number the 1492-byte WAN
        // needs a client to see.
        if (next == 58 && packet.Length >= 41)
        {
            var type = packet[40];
            var detail = type switch
            {
                135 or 136 when packet.Length >= 64 => $" target={V6Address(packet.Slice(48, 16))}",
                2 when packet.Length >= 48 => $" mtu={BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(44, 4))}",
                _ => "",
            };
            return $"{name} type={type}{detail} {src} -> {dst}";
        }
        // Refused is its own answer: a fragment, a §4.7 No Next Header or a header with no length figure
        // to read names no transport, and the trace says what it is looking at rather than inventing one.
        if (!TlsMitm.Ipv6Chain.TryFind(packet, out var chain)) return $"{name} {src} -> {dst}";
        if (chain.Transport > TlsMitm.Ipv6Chain.HeaderLength)
            name += $">{(chain.Protocol == 6 ? "tcp" : "udp")}";
        var sport = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(chain.Transport, 2));
        var dport = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(chain.Transport + 2, 2));
        return $"{name} {src}:{sport} -> {dst}:{dport}";
    }

    private static string V6Address(ReadOnlySpan<byte> sixteen) => new IPAddress(sixteen.ToArray()).ToString();

    // What the trace prints. The clauses differ per layer on purpose:
    //   - the interface pair is the main filter's own condition, so it belongs to the forward run, where
    //     it means "this is a packet the main handle is being asked about";
    //   - at the network layer the same clause means "everything this host is sent", which is the host's
    //     own traffic - measured on a live run, it spent the whole budget in seconds and printed none of
    //     the client. There the LAN-subnet and mapped-port clauses are what single a client's flow out;
    //   - the mapped-port clause is the one that catches a NAT reply, and it is why both layers are worth
    //     watching: an answer to a SNATed client arrives at this host's WAN address with the mapped port in
    //     its destination, so whichever layer prints it is the layer a rewrite can happen at.
    // The limited broadcast is deliberately not a clause of its own: a DHCPDISCOVER reaches the lease
    // server through the LAN interface, so the interface clause already covers it, while another segment's
    // broadcasts bridged onto the WAN used to fill the screen and spend the whole budget.
    private static bool WorthPrinting(ReadOnlySpan<byte> packet, int ifIdx, int lanIfIdx, int wanIfIdx,
        bool forward, uint network, uint lanMask, Func<byte, ushort, bool> isMappedPort, bool v6)
    {
        // An IPv6 packet has neither a subnet to test nor a mapping table to consult - the delegated prefix
        // is not NATed, so the interface is the only thing that singles a client's packet out of this
        // host's own v6 traffic. At the network layer that is the LAN alone: the WAN index is where the
        // host's own delegated-prefix traffic arrives, and printing it spends the budget the same way the
        // host's own v4 traffic did.
        if (v6)
            return packet.Length >= 40
                   && (forward ? ifIdx == lanIfIdx || ifIdx == wanIfIdx : ifIdx == lanIfIdx);
        if (forward && (ifIdx == lanIfIdx || ifIdx == wanIfIdx)) return true;
        if (packet.Length < 20 || (packet[0] >> 4) != 4) return false;
        var src = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(12, 4));
        var dst = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(16, 4));
        if ((src & lanMask) == network || (dst & lanMask) == network) return true;
        return TryPorts(packet, out var proto, out var sport, out var dport)
               && (isMappedPort(proto, sport) || isMappedPort(proto, dport));
    }

    private static bool TryPorts(ReadOnlySpan<byte> packet, out byte proto, out ushort sport, out ushort dport)
    {
        proto = 0;
        sport = 0;
        dport = 0;
        var ihl = (packet[0] & 0x0F) * 4;
        if (packet.Length < ihl + 8) return false;
        proto = packet[9];
        if (proto == 1)
        {
            // An ICMP query carries its Identifier where a port pair would be, and that identifier is what
            // the mapping table keys on, so both halves of the pair read as the same number here.
            sport = dport = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ihl + 4, 2));
            return true;
        }
        if (proto is not (6 or 17)) return false;
        sport = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ihl, 2));
        dport = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ihl + 2, 2));
        return true;
    }

    // One of these runs per leg under --trace - the forward and network layers for each address family,
    // each with its own budget. `forward` is the handle the main loop is written against, so it is the one
    // that can be asked whether it would take a packet; the network-layer run only reports what arrives,
    // because a verdict about the main handle would be a verdict about a layer that packet never reached.
    // `v6` selects the IPv6 legs, which have no main handle to be a verdict about (see the take= note below).
    public static unsafe void TraceLoop(WinDivertHandle sniffer, CancellationToken ct, int budget, string tag,
        bool forward, uint lanAddr, uint lanMask, int lanIfIdx, int wanIfIdx,
        Func<byte, ushort, bool> isMappedPort, bool v6 = false)
    {
        var packetBuf = Marshal.AllocHGlobal(MTU_MAX);
        var addrBuf = Marshal.AllocHGlobal(ADDR_SIZE);
        var remaining = budget;
        var seen = 0;
        var network = lanAddr & lanMask;
        try
        {
            while (!ct.IsCancellationRequested && remaining > 0)
            {
                int recvLen;
                if (!sniffer.Recv((void*)packetBuf, MTU_MAX, &recvLen, (Address*)addrBuf))
                {
                    if (ct.IsCancellationRequested) break;
                    continue;
                }
                seen++;
                var packet = new ReadOnlySpan<byte>((void*)packetBuf, recvLen);
                var addr = (Address*)addrBuf;
                if (!WorthPrinting(packet, addr->IfIdx, lanIfIdx, wanIfIdx, forward, network, lanMask, isMappedPort, v6))
                    continue;
                remaining--;
                var outbound = (addr->Flags & AddressFlag.Outbound) != 0;
                var impostor = (addr->Flags & AddressFlag.Impostor) != 0;
                var loopback = (addr->Flags & AddressFlag.Loopback) != 0;
                // The main handle's own two conditions, evaluated here on the packet the sniff handle saw.
                // Without this, a run that shows transit packets and no rewrite reads as a broken decision
                // tree when it is the filter declining the packet, and the two look identical from the
                // counters. It is only meaningful on a leg the main handle shares, and Router's main filter
                // is `ip` - IPv4 - so a v6 line has no verdict to report: printing one would claim a capture
                // that the filter cannot make.
                var verdict = "";
                if (forward && !v6)
                {
                    var take = !impostor && (addr->IfIdx == lanIfIdx || addr->IfIdx == wanIfIdx);
                    var why = impostor ? "impostor" : take ? "yes" : $"ifIdx!={lanIfIdx}|{wanIfIdx}";
                    verdict = $"take={why,-16} ";
                }
                var describe = Describe(packet);
                Console.WriteLine($"[Trace {tag}] ifIdx={addr->IfIdx,-4} dir={(outbound ? "out" : "in"),-3} " +
                                  $"impostor={impostor,-5} loopback={loopback,-5} " + verdict +
                                  $"len={recvLen,-5} {describe}");
            }
            // Printed on the way out whether or not the budget ran out: a run that shows no lines has to
            // read as "the predicate matched nothing" rather than "the handle saw nothing", which is the
            // difference between a wrong clause and a wrong layer.
            Console.WriteLine($"[Trace {tag}] saw {seen} packets, printed {budget - remaining}" +
                              (remaining == 0 ? $" (budget of {budget} spent)" : ""));
        }
        finally
        {
            sniffer.Shutdown(ShutdownMode.Recv);
            Marshal.FreeHGlobal(packetBuf);
            Marshal.FreeHGlobal(addrBuf);
        }
    }

    // The uint form used throughout this project is the four octets read big-endian, so 192.168.2.1 is
    // 0xC0A80201. Both directions of the conversion go through the octet array, which is the one
    // representation whose order a caller can read off the code.
    public static uint ToBigEndian(IPAddress address)
        => BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes());

    public static IPAddress ToIpAddress(uint address)
        => new(new byte[] { (byte)(address >> 24), (byte)(address >> 16), (byte)(address >> 8), (byte)address });

    // 169.254.0.0/16 is an APIPA fallback, not an interface anyone configured: offering it as the
    // LAN side would produce a router that forwards to nothing.
    private static bool IsLinkLocal(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        return bytes.Length == 4 && bytes[0] == 169 && bytes[1] == 254;
    }
}
