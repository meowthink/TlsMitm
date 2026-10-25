using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using static TlsMitm.WinDivertPInvoke;

namespace TlsMitm;

// The proxy needs three redirector services; the seam lets the offline harness drive the real
// proxy without WinDivert.
public interface IRedirector
{
    (IPAddress ip, int port)? LookupOriginalDest(IPAddress clientIp, int clientPort, IPAddress serverIp);
    void RegisterExemption(int sourcePort);
    void UnregisterExemption(int sourcePort);

    // Requests aimed at a loopback listener this process owns (the CRL endpoint) are answered locally.
    void RegisterLocalService(int dstPort);
}

public class PacketRedirector : IRedirector, IDisposable
{
    private readonly WinDivertHandle _divert;
    private readonly int _relayPort;
    private readonly ConcurrentDictionary<V4Key, ConnInfo> _v4Conns = new();
    private readonly ConcurrentDictionary<V6Key, ConnInfo> _v6Conns = new();
    private readonly ConcurrentDictionary<int, byte> _exemptPorts = new();
    private readonly ConcurrentDictionary<int, byte> _localServicePorts = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly IntPtr _pPacket;
    private readonly IntPtr _pAddr;
    private Task? _runTask;
    private long _reverseMiss;
    private long _forwardMiss;
    private long _v6NotTcp;
    private int _disposed;

    public unsafe PacketRedirector(int relayPort)
    {
        _relayPort = relayPort;
        _divert = new WinDivertHandle("outbound and tcp and not impostor");
        _pPacket = Marshal.AllocHGlobal(MTU_MAX);
        _pAddr = Marshal.AllocHGlobal(ADDR_SIZE);
        new Span<byte>((void*)_pPacket, MTU_MAX).Clear();
        new Span<byte>((void*)_pAddr, ADDR_SIZE).Clear();
        Console.WriteLine($"[Redirector] Filter: outbound and tcp and not impostor");
        Console.WriteLine($"[Redirector] Relay port: {_relayPort}");
    }

    public (IPAddress ip, int port)? LookupOriginalDest(IPAddress clientIp, int clientPort, IPAddress serverIp)
    {
        if (serverIp.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var (srcHi, srcLo) = RawV6(clientIp);
            var (dstHi, dstLo) = RawV6(serverIp);
            return _v6Conns.TryGetValue(new V6Key(srcHi, srcLo, (ushort)clientPort, dstHi, dstLo), out var info)
                ? (info.OrigDstAddr, info.OrigDstPort)
                : null;
        }

        return _v4Conns.TryGetValue(new V4Key(RawV4(clientIp), (ushort)clientPort, RawV4(serverIp)), out var info4)
            ? (info4.OrigDstAddr, info4.OrigDstPort)
            : null;
    }

    private static uint RawV4(IPAddress addr) => BitConverter.ToUInt32(addr.GetAddressBytes());

    private static (ulong Hi, ulong Lo) RawV6(IPAddress addr)
    {
        var bytes = addr.GetAddressBytes();
        return (BitConverter.ToUInt64(bytes.AsSpan(0, 8)), BitConverter.ToUInt64(bytes.AsSpan(8, 8)));
    }

    public void RegisterExemption(int sourcePort)
    {
        _exemptPorts[sourcePort] = 1;
        Console.WriteLine($"[Redirector] EXEMPT +{sourcePort} ({_exemptPorts.Count} held)");
    }

    public void UnregisterExemption(int sourcePort)
    {
        if (_exemptPorts.TryRemove(sourcePort, out _))
            Console.WriteLine($"[Redirector] EXEMPT -{sourcePort} ({_exemptPorts.Count} held)");
    }

    public void RegisterLocalService(int dstPort)
    {
        _localServicePorts[dstPort] = 1;
        Console.WriteLine($"[Redirector] LOCAL +{dstPort} ({_localServicePorts.Count} held)");
    }

    public Task StartAsync()
    {
        _ = Task.Run(() => CleanupLoop(_cts.Token));
        _runTask = Task.Run(() => Run(_cts.Token));
        return Task.CompletedTask;
    }

    private void Run(CancellationToken ct)
    {
        Console.WriteLine("[Redirector] Started");

        while (!ct.IsCancellationRequested)
        {
            try
            {
                unsafe { RunOnce(ct); }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { Console.WriteLine($"[Redirector] Error: {ex.Message}"); }
        }
    }

    private unsafe void RunOnce(CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        int recvLen;
        if (!_divert.Recv((void*)_pPacket, MTU_MAX, &recvLen, (Address*)_pAddr))
            return;

        var version = (*(byte*)_pPacket >> 4) & 0x0F;

        if (version == 4 && recvLen >= sizeof(NativeIpv4Header))
        {
            var ip4 = (NativeIpv4Header*)_pPacket;
            if (ip4->Protocol == 6 && recvLen >= ip4->HeaderLength + sizeof(NativeTcpHeader))
            {
                var tcp = (NativeTcpHeader*)((byte*)_pPacket + ip4->HeaderLength);
                ProcessV4(recvLen, ip4, tcp);
            }
            else
            {
                _divert.Send((void*)_pPacket, recvLen, null, (Address*)_pAddr);
            }
        }
        else if (version == 6 && recvLen >= sizeof(NativeIpv6Header))
        {
            var ip6 = (NativeIpv6Header*)_pPacket;
            if (ip6->NextHeader == 6 && recvLen >= sizeof(NativeIpv6Header) + sizeof(NativeTcpHeader))
            {
                var tcp = (NativeTcpHeader*)((byte*)_pPacket + sizeof(NativeIpv6Header));
                ProcessV6(recvLen, ip6, tcp);
            }
            else
            {
                // An extension header (a fragment, above all) means the TCP header is not where the
                // rewrite expects it, and a fragment cannot be NATed without rebuilding the whole
                // datagram. Such a flow goes out untouched, so say so rather than let it look like
                // a session that was intercepted and simply never appeared.
                var ext = Interlocked.Increment(ref _v6NotTcp);
                if (ext <= 20)
                    Console.WriteLine($"[Redirector] PASS v6 next-header={ip6->NextHeader} (extension header, not rewritten)");
                _divert.Send((void*)_pPacket, recvLen, null, (Address*)_pAddr);
            }
        }
        else
        {
            _divert.Send((void*)_pPacket, recvLen, null, (Address*)_pAddr);
        }
    }

    private unsafe void ProcessV4(int recvLen, NativeIpv4Header* ip4, NativeTcpHeader* tcp)
    {
        var srcPort = NetToHost(tcp->SrcPort);
        var dstPort = NetToHost(tcp->DstPort);

        if (_exemptPorts.ContainsKey(srcPort))
        {
            _divert.Send((void*)_pPacket, recvLen, null, (Address*)_pAddr);
            return;
        }

        // Loopback is in the condition so this stays "traffic to our own endpoint", never a
        // destination-port exclusion that would let a real server on 8873 through unmitm'd.
        if (IsIPv4Loopback(ip4->DstAddr) && _localServicePorts.ContainsKey(dstPort))
        {
            _divert.Send((void*)_pPacket, recvLen, null, (Address*)_pAddr);
            return;
        }

        var isSyn = (tcp->Flags & TcpFlag.Syn) != 0 && (tcp->Flags & TcpFlag.Ack) == 0;
        var isFinOrRst = (tcp->Flags & (TcpFlag.Fin | TcpFlag.Rst)) != 0;

        if (srcPort == _relayPort)
            ReverseSwapV4(recvLen, ip4, tcp, dstPort, isFinOrRst);
        else if (dstPort != _relayPort)
            ForwardSwapV4(recvLen, ip4, tcp, srcPort, dstPort, isSyn, isFinOrRst);
        else
            _divert.Send((void*)_pPacket, recvLen, null, (Address*)_pAddr);
    }

    private unsafe void ForwardSwapV4(int recvLen, NativeIpv4Header* ip4, NativeTcpHeader* tcp,
        int srcPort, int dstPort, bool isSyn, bool isFinOrRst)
    {
        var srcAddr = ip4->SrcAddr;
        var dstAddr = ip4->DstAddr;
        var key = new V4Key(srcAddr, (ushort)srcPort, dstAddr);
        var isLoopback = IsIPv4Loopback(srcAddr) && IsIPv4Loopback(dstAddr);

        if (isSyn)
        {
            _v4Conns[key] = new ConnInfo(new IPAddress(dstAddr), dstPort);
            Console.WriteLine($"[Redirector] NEW v4 {new IPAddress(srcAddr)}:{srcPort} -> {new IPAddress(dstAddr)}:{dstPort}");
        }

        if (!_v4Conns.TryGetValue(key, out var entry))
        {
            var fwdMiss = Interlocked.Increment(ref _forwardMiss);
            if (fwdMiss <= 30)
                Console.WriteLine($"[Redirector] Fwd v4 MISS key={srcPort} {new IPAddress(srcAddr)}:{srcPort} -> {new IPAddress(dstAddr)}:{dstPort} flags={tcp->Flags}");
            _divert.Send((void*)_pPacket, recvLen, null, (Address*)_pAddr);
            return;
        }

        entry.LastSeen = DateTime.UtcNow;

        tcp->DstPort = HostToNet((ushort)_relayPort);

        bool calcOk = false;
        int routeErr = 0;
        if (!isLoopback)
        {
            ip4->SrcAddr = dstAddr;
            ip4->DstAddr = srcAddr;
            ((Address*)_pAddr)->Flags &= ~AddressFlag.Outbound;
            calcOk = _divert.CalcOutboundFlag((void*)_pPacket, (Address*)_pAddr, out routeErr);
        }

        _divert.CalcChecksums((void*)_pPacket, recvLen, (Address*)_pAddr);
        var sent = _divert.Send((void*)_pPacket, recvLen, null, (Address*)_pAddr);
        if (isSyn && !isLoopback)
            Console.WriteLine($"[Redirector] Fwd v4 {new IPAddress(srcAddr)}:{srcPort}->{new IPAddress(dstAddr)}:{dstPort} calc={calcOk} routeErr={routeErr} flags={((Address*)_pAddr)->Flags} sent={sent}");

        if (isFinOrRst)
        {
            // Keep translating after a FIN/RST: the peer still owes ACKs, and releasing the
            // proxy's reply to the real server makes it answer with an RST onto the live client socket.
            entry.Closing = true;
        }
    }

    private unsafe void ReverseSwapV4(int recvLen, NativeIpv4Header* ip4, NativeTcpHeader* tcp,
        int dstPort, bool isFinOrRst)
    {
        var srcAddr = ip4->SrcAddr;
        var dstAddr = ip4->DstAddr;
        var key = new V4Key(srcAddr, (ushort)dstPort, dstAddr);

        if (!_v4Conns.TryGetValue(key, out var conn))
        {
            var miss = Interlocked.Increment(ref _reverseMiss);
            if (miss <= 200)
                Console.WriteLine($"[Redirector] Rev v4 MISS key={dstPort} flags={tcp->Flags} (relay<->{new IPAddress(dstAddr)})");
            _divert.Send((void*)_pPacket, recvLen, null, (Address*)_pAddr);
            return;
        }

        conn.LastSeen = DateTime.UtcNow;

        var isLoopback = IsIPv4Loopback(srcAddr) && IsIPv4Loopback(dstAddr);

        if (!isLoopback)
        {
            ip4->SrcAddr = dstAddr;
            ip4->DstAddr = srcAddr;
        }

        tcp->SrcPort = HostToNet((ushort)conn.OrigDstPort);

        _divert.CalcChecksums((void*)_pPacket, recvLen, (Address*)_pAddr);
        var sent = _divert.Send((void*)_pPacket, recvLen, null, (Address*)_pAddr);
        conn.RevCount++;
        if (conn.RevCount <= 3)
            Console.WriteLine($"[Redirector] Rev v4 k={dstPort} n={conn.RevCount} -> {conn.OrigDstAddr}:{conn.OrigDstPort} loopback={isLoopback} flags={tcp->Flags} sent={sent}");

        if (isFinOrRst)
            conn.Closing = true;
    }

    private unsafe void ProcessV6(int recvLen, NativeIpv6Header* ip6, NativeTcpHeader* tcp)
    {
        var srcPort = NetToHost(tcp->SrcPort);
        var dstPort = NetToHost(tcp->DstPort);

        if (_exemptPorts.ContainsKey(srcPort))
        {
            _divert.Send((void*)_pPacket, recvLen, null, (Address*)_pAddr);
            return;
        }

        if (IsIPv6Loopback(V6Destination(ip6)) && _localServicePorts.ContainsKey(dstPort))
        {
            _divert.Send((void*)_pPacket, recvLen, null, (Address*)_pAddr);
            return;
        }

        var isSyn = (tcp->Flags & TcpFlag.Syn) != 0 && (tcp->Flags & TcpFlag.Ack) == 0;
        var isFinOrRst = (tcp->Flags & (TcpFlag.Fin | TcpFlag.Rst)) != 0;

        if (srcPort == _relayPort)
            ReverseSwapV6(recvLen, ip6, tcp, dstPort, isFinOrRst);
        else if (dstPort != _relayPort)
            ForwardSwapV6(recvLen, ip6, tcp, srcPort, dstPort, isSyn, isFinOrRst);
        else
            _divert.Send((void*)_pPacket, recvLen, null, (Address*)_pAddr);
    }

    private unsafe void ForwardSwapV6(int recvLen, NativeIpv6Header* ip6, NativeTcpHeader* tcp,
        int srcPort, int dstPort, bool isSyn, bool isFinOrRst)
    {
        var srcAddrBytes = new byte[16];
        var dstAddrBytes = new byte[16];
        for (int i = 0; i < 16; i++)
        {
            srcAddrBytes[i] = ip6->SourceAddress[i];
            dstAddrBytes[i] = ip6->DestinationAddress[i];
        }

        var srcAddr = new IPAddress(srcAddrBytes);
        var dstAddr = new IPAddress(dstAddrBytes);
        var isLoopback = IsIPv6Loopback(srcAddr) && IsIPv6Loopback(dstAddr);

        var key = MakeV6Key(srcAddr, srcPort, dstAddr);

        if (isSyn)
        {
            _v6Conns[key] = new ConnInfo(dstAddr, dstPort);
            Console.WriteLine($"[Redirector] NEW v6 {srcAddr}:{srcPort} -> {dstAddr}:{dstPort}");
        }

        if (!_v6Conns.TryGetValue(key, out var entry))
        {
            var v6Miss = Interlocked.Increment(ref _forwardMiss);
            if (v6Miss <= 30)
                Console.WriteLine($"[Redirector] Fwd v6 MISS key={srcPort} {srcAddr}:{srcPort} -> {dstAddr}:{dstPort} flags={tcp->Flags}");
            _divert.Send((void*)_pPacket, recvLen, null, (Address*)_pAddr);
            return;
        }

        entry.LastSeen = DateTime.UtcNow;

        tcp->DstPort = HostToNet((ushort)_relayPort);

        if (!isLoopback)
        {
            for (int i = 0; i < 16; i++)
            {
                ip6->SourceAddress[i] = dstAddrBytes[i];
                ip6->DestinationAddress[i] = srcAddrBytes[i];
            }
            ((Address*)_pAddr)->Flags &= ~AddressFlag.Outbound;
            _divert.CalcOutboundFlag((void*)_pPacket, (Address*)_pAddr);
        }

        _divert.CalcChecksums((void*)_pPacket, recvLen, (Address*)_pAddr);
        _divert.Send((void*)_pPacket, recvLen, null, (Address*)_pAddr);

        if (isFinOrRst)
            entry.Closing = true;
    }

    private unsafe void ReverseSwapV6(int recvLen, NativeIpv6Header* ip6, NativeTcpHeader* tcp,
        int dstPort, bool isFinOrRst)
    {
        var srcAddrBytes = new byte[16];
        var dstAddrBytes = new byte[16];
        for (int i = 0; i < 16; i++)
        {
            srcAddrBytes[i] = ip6->SourceAddress[i];
            dstAddrBytes[i] = ip6->DestinationAddress[i];
        }

        var srcAddr = new IPAddress(srcAddrBytes);
        var dstAddr = new IPAddress(dstAddrBytes);
        var isLoopback = IsIPv6Loopback(srcAddr) && IsIPv6Loopback(dstAddr);

        if (!_v6Conns.TryGetValue(MakeV6Key(srcAddr, dstPort, dstAddr), out var conn))
        {
            var miss6 = Interlocked.Increment(ref _reverseMiss);
            if (miss6 <= 200)
                Console.WriteLine($"[Redirector] Rev v6 MISS key={dstPort} flags={tcp->Flags}");
            _divert.Send((void*)_pPacket, recvLen, null, (Address*)_pAddr);
            return;
        }

        conn.LastSeen = DateTime.UtcNow;

        if (!isLoopback)
        {
            for (int i = 0; i < 16; i++)
            {
                ip6->SourceAddress[i] = dstAddrBytes[i];
                ip6->DestinationAddress[i] = srcAddrBytes[i];
            }
        }

        tcp->SrcPort = HostToNet((ushort)conn.OrigDstPort);

        _divert.CalcChecksums((void*)_pPacket, recvLen, (Address*)_pAddr);
        _divert.Send((void*)_pPacket, recvLen, null, (Address*)_pAddr);

        if (isFinOrRst)
            conn.Closing = true;
    }

    private static bool IsIPv4Loopback(uint addr)
    {
        return (addr & 0xFF) == 127;
    }

    private static bool IsIPv6Loopback(IPAddress addr)
    {
        var bytes = addr.GetAddressBytes();
        if (bytes.Length != 16) return false;
        for (int i = 0; i < 15; i++)
            if (bytes[i] != 0) return false;
        return bytes[15] == 1;
    }

    private static unsafe IPAddress V6Destination(NativeIpv6Header* ip6)
    {
        var bytes = new byte[16];
        for (int i = 0; i < 16; i++)
            bytes[i] = ip6->DestinationAddress[i];
        return new IPAddress(bytes);
    }

    private async Task CleanupLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromSeconds(5), ct);
            Sweep(_v4Conns, "v4");
            Sweep(_v6Conns, "v6");
        }
    }

    private static void Sweep<T>(ConcurrentDictionary<T, ConnInfo> table, string family) where T : struct
    {
        var idleCutoff = DateTime.UtcNow.AddMinutes(-5);
        var closingCutoff = DateTime.UtcNow.AddSeconds(-10);
        foreach (var kvp in table)
        {
            var cutoff = kvp.Value.Closing ? closingCutoff : idleCutoff;
            if (kvp.Value.LastSeen < cutoff && table.TryRemove(kvp.Key, out _))
                Console.WriteLine($"[Redirector] DROP {family} {kvp.Value.OrigDstAddr}:{kvp.Value.OrigDstPort} reason={(kvp.Value.Closing ? "closed" : "idle")} rev={kvp.Value.RevCount}");
        }
    }

    private static V6Key MakeV6Key(IPAddress src, int srcPort, IPAddress dst)
    {
        var (srcHi, srcLo) = RawV6(src);
        var (dstHi, dstLo) = RawV6(dst);
        return new V6Key(srcHi, srcLo, (ushort)srcPort, dstHi, dstLo);
    }

    private readonly record struct V4Key(uint SrcIp, ushort SrcPort, uint DstIp);

    private readonly record struct V6Key(ulong SrcHi, ulong SrcLo, ushort SrcPort, ulong DstHi, ulong DstLo);

    public void Dispose()
    {
        // Program.cs disposes this explicitly and then again through `using var`; the second pass
        // would Cancel a disposed CTS and free the same native buffers twice.
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _cts.Cancel();
        _divert.Shutdown();
        _runTask?.Wait(TimeSpan.FromSeconds(2));
        _divert.Dispose();
        Marshal.FreeHGlobal(_pPacket);
        Marshal.FreeHGlobal(_pAddr);
        _cts.Dispose();
    }

    private class ConnInfo
    {
        public IPAddress OrigDstAddr;
        public int OrigDstPort;
        public DateTime LastSeen = DateTime.UtcNow;
        public int RevCount;
        public bool Closing;

        public ConnInfo(IPAddress origDstAddr, int origDstPort)
        {
            OrigDstAddr = origDstAddr;
            OrigDstPort = origDstPort;
        }
    }
}
