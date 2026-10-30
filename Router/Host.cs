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
    public static string? OptionValue(string[] args, string name)
    {
        var index = Array.IndexOf(args, name);
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }

    // For the options that are given more than once, one value per thing configured.
    public static List<string> OptionValues(string[] args, string name)
    {
        var found = new List<string>();
        for (var i = 0; i + 1 < args.Length; i++)
            if (args[i] == name) found.Add(args[i + 1]);
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
    public static string? QueryForwarding(int ifIdx)
    {
        var output = RunPowerShell($"(Get-NetIPInterface -InterfaceIndex {ifIdx} -AddressFamily IPv4).Forwarding");
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

    public static void SetForwarding(int ifIdx)
    {
        // Same reason `StopService` reads the error stream now: this call fails in a shell that is not
        // elevated, and a stdout-only runner printed "done" over it. The state is re-queried by the caller
        // either way, but the refusal's own words belong on the record.
        var output = RunPowerShell($"Set-NetIPInterface -InterfaceIndex {ifIdx} -Forwarding Enabled -ErrorAction Stop",
            withStdErr: true);
        Console.WriteLine(output is { Length: > 0 }
            ? $"[Router] Set-NetIPInterface {ifIdx}: {output.Trim()}"
            : $"[Router] Set-NetIPInterface {ifIdx}: done");
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
            if (process is null) return null;
            // A cmdlet writes its error records to stderr, where a caller that only reads stdout cannot see
            // them. Drained concurrently because a child that fills the error buffer blocks there, and the
            // stdout read above would then never return.
            var errorRead = process.StandardError.ReadToEndAsync();
            var stdout = process.StandardOutput.ReadToEnd();
            process.WaitForExit(15000);
            var stderr = errorRead.Wait(2000) ? errorRead.Result : "";
            return withStdErr && stderr.Trim().Length > 0
                ? stdout.Trim() + "\n" + stderr.Trim()
                : stdout;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Router] PowerShell query failed: {ex.Message}");
            return null;
        }
    }

    public static string Describe(ReadOnlySpan<byte> packet)
    {
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
        bool forward, uint network, uint lanMask, Func<byte, ushort, bool> isMappedPort)
    {
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

    // Two of these run under --trace, one per layer, each with its own budget. `forward` is the handle
    // the main loop is written against, so it is the one that can be asked whether it would take a
    // packet; the network-layer run only reports what arrives, because a verdict about the main handle
    // would be a verdict about a layer that packet never reached.
    public static unsafe void TraceLoop(WinDivertHandle sniffer, CancellationToken ct, int budget, string tag,
        bool forward, uint lanAddr, uint lanMask, int lanIfIdx, int wanIfIdx,
        Func<byte, ushort, bool> isMappedPort)
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
                if (!WorthPrinting(packet, addr->IfIdx, lanIfIdx, wanIfIdx, forward, network, lanMask, isMappedPort))
                    continue;
                remaining--;
                var outbound = (addr->Flags & AddressFlag.Outbound) != 0;
                var impostor = (addr->Flags & AddressFlag.Impostor) != 0;
                var loopback = (addr->Flags & AddressFlag.Loopback) != 0;
                // The main handle's own two conditions, evaluated here on the packet the sniff handle saw.
                // Without this, a run that shows transit packets and no rewrite reads as a broken decision
                // tree when it is the filter declining the packet, and the two look identical from the
                // counters.
                var take = !impostor && (addr->IfIdx == lanIfIdx || addr->IfIdx == wanIfIdx);
                var why = impostor ? "impostor" : take ? "yes" : $"ifIdx!={lanIfIdx}|{wanIfIdx}";
                var describe = Describe(packet);
                Console.WriteLine($"[Trace {tag}] ifIdx={addr->IfIdx,-4} dir={(outbound ? "out" : "in"),-3} " +
                                  $"impostor={impostor,-5} loopback={loopback,-5} " +
                                  (forward ? $"take={why,-16} " : "") +
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
