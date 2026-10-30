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
    /// What an intercepted connection was really aimed at, and who sent it. The rewrite leaves the
    /// accepted socket holding the local endpoint it was delivered to and a source port that is the
    /// flow's token, so the client's own address and port only exist here. Asking names the caller the
    /// session that will relay this flow, until <see cref="ReleaseFlow"/> says otherwise.
    OriginalDest? LookupOriginalDest(IPAddress deliveredTo, int token, IPAddress serverAddr);

    /// The session that looked the flow up is over: hand it back to the redirector's own closing clock,
    /// which is what carries its FIN out. An unanswered token is a flow no one is relaying, and silence
    /// alone cannot be trusted to end one.
    void ReleaseFlow(int token);

    // A listening socket this process owns (the CRL endpoint): its port is stable for the whole run,
    // so the port alone names the traffic to leave alone.
    void RegisterExemption(int sourcePort);
    void UnregisterExemption(int sourcePort);

    // One outbound connection this process opened to reach a real server. Its source port is an
    // ephemeral one the OS handed out, so the port alone would also exempt whatever connection gets
    // that port next; the destination is part of the identity of the flow being exempted.
    void RegisterFlowExemption(int sourcePort, IPAddress destination, int destinationPort);
    void UnregisterFlowExemption(int sourcePort, IPAddress destination, int destinationPort);

    // Requests aimed at a loopback listener this process owns (the CRL endpoint) are answered locally.
    void RegisterLocalService(int dstPort);
}

public readonly record struct OriginalDest(IPAddress OrigAddr, int OrigPort, IPAddress ClientAddr, int ClientPort);

public class PacketRedirector : IRedirector, IDisposable
{
    // One capture per leg, each with its own handle and its own packet buffers, and both feeding the
    // same ProcessV4/ProcessV6: the LAN side is a second place to pick a packet up from, not a second
    // pipeline.
    private readonly Capture _local;
    private readonly Capture? _lan;
    private readonly int _relayPort;
    private readonly ProcessFilter? _filter;
    private readonly FlowTable _flows = new();
    private readonly ConcurrentDictionary<int, byte> _exemptPorts = new();
    private readonly ConcurrentDictionary<V4ExemptKey, byte> _v4ExemptFlows = new();
    private readonly ConcurrentDictionary<V6ExemptKey, byte> _v6ExemptFlows = new();
    private readonly ConcurrentDictionary<int, byte> _localServicePorts = new();
    private readonly CancellationTokenSource _cts = new();
    private Task? _runTask;
    private Task? _lanTask;
    private long _reverseMiss;
    private long _forwardMiss;
    private long _v6NotTcp;
    private long _fragPassed;
    private int _disposed;

    public PacketRedirector(int relayPort, ProcessFilter? filter = null, LanSide? lan = null)
    {
        _relayPort = relayPort;
        _filter = filter;
        _local = new Capture(new WinDivertHandle("outbound and tcp and not impostor"), null);
        // A forwarded client's packet is never offered to an outbound network-layer filter, which is
        // why this leg needs a capture at the layer that sees transit traffic. Priority 0 puts it above
        // a Router's -100 on the same layer, so the client's packet is seen before anything else has
        // rewritten it.
        _lan = lan == null ? null : new Capture(new WinDivertHandle(lan.TcpFilter, Layer.Forward), lan);
        Console.WriteLine($"[Redirector] Filter: outbound and tcp and not impostor");
        Console.WriteLine($"[Redirector] Relay port: {_relayPort}");
        if (filter is { IsActive: true })
            Console.WriteLine($"[Redirector] Scope: {filter.Describe()}; other flows are relayed by the OS");
        if (lan != null)
        {
            Console.WriteLine($"[Redirector] LAN capture: {lan.TcpFilter}");
            Console.WriteLine($"[Redirector] LAN side: {lan.Address} ifIdx={lan.IfIdx}; a forwarded packet is delivered to it");
        }
    }

    public OriginalDest? LookupOriginalDest(IPAddress deliveredTo, int token, IPAddress serverAddr)
    {
        // The token is the whole key: it is handed out one connection at a time, so no two live flows -
        // in either family - carry it. The two addresses are in the signature for an implementation
        // with no packet state of its own, which has to read them off the socket it was handed.
        var state = _flows.ByToken(unchecked((ushort)token));
        if (state == null) return null;
        // A session has this flow: its end is the answer to "when is this connection over", and a quiet
        // minute is not.
        state.Session = true;
        return new OriginalDest(state.OrigDstAddr, state.OrigDstPort, state.ClientAddr, state.ClientPort);
    }

    public void ReleaseFlow(int token) => _flows.EndSession(unchecked((ushort)token));

    /// Send the relay's inbound reachability probe: one SYN from inside the LAN subnet to this host's own
    /// relay port, put in exactly the way a client's rewritten packet is put in. Returns the port the probe
    /// carried, which is what the caller looks for in the TCP table, or zero when nothing was sent. The
    /// filter that decides the answer is the one that sees the packet, so the firewall's rule store cannot
    /// answer this (see InboundFirewall). No session is made: the probe is a lone SYN, and the proxy is
    /// never involved in the verdict.
    public unsafe ushort InjectRelayProbe(IPAddress source)
    {
        if (_lan?.Lan is not { } lan)
        {
            Console.WriteLine("[Redirector] probe needs --lan: an inbound path to the relay is what is being asked about");
            return 0;
        }
        var token = _flows.FreeToken();
        if (token == 0)
        {
            Console.WriteLine("[Redirector] probe not sent: the token pool is full");
            return 0;
        }

        var packet = RelayProbe.BuildSyn(source, lan.Address, token, unchecked((ushort)_relayPort));
        var address = stackalloc Address[1];
        new Span<byte>(address, ADDR_SIZE).Clear();
        // The direction of an injected packet is this field alone, and this one has to arrive. The index
        // names the interface that owns the destination address, which is what strong-host receive
        // requires (RFC 1122 §3.3.4.2; measured on this host's AP adapter as 5/0).
        address->Flags = AddressFlag.None;
        address->IfIdx = lan.IfIdx;
        var buffer = Marshal.AllocHGlobal(packet.Length);
        try
        {
            Marshal.Copy(packet, 0, buffer, packet.Length);
            _local.Handle.CalcChecksums((void*)buffer, packet.Length, address);
            var sent = _local.Handle.Send((void*)buffer, packet.Length, null, address);
            Console.WriteLine($"[Redirector] inbound probe: SYN {source}:{token} -> {lan.Address}:{_relayPort}" +
                              $" ifIdx={address->IfIdx}/{address->SubIfIdx} sent={sent}");
            return sent ? token : (ushort)0;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static uint RawV4(IPAddress addr) => BitConverter.ToUInt32(addr.GetAddressBytes());

    private static (ulong Hi, ulong Lo) RawV6(IPAddress addr)
    {
        var bytes = addr.GetAddressBytes();
        return (BitConverter.ToUInt64(bytes.AsSpan(0, 8)), BitConverter.ToUInt64(bytes.AsSpan(8, 8)));
    }

    private static unsafe (ulong Hi, ulong Lo) ReadV6(byte* addr) =>
        (BitConverter.ToUInt64(new ReadOnlySpan<byte>(addr, 8)), BitConverter.ToUInt64(new ReadOnlySpan<byte>(addr + 8, 8)));

    private static unsafe void WriteV6(byte* addr, ulong hi, ulong lo)
    {
        BitConverter.TryWriteBytes(new Span<byte>(addr, 8), hi);
        BitConverter.TryWriteBytes(new Span<byte>(addr + 8, 8), lo);
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

    public void RegisterFlowExemption(int sourcePort, IPAddress destination, int destinationPort)
    {
        if (destination.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var (hi, lo) = RawV6(destination);
            _v6ExemptFlows[new V6ExemptKey((ushort)sourcePort, hi, lo, (ushort)destinationPort)] = 1;
        }
        else
        {
            _v4ExemptFlows[new V4ExemptKey((ushort)sourcePort, RawV4(destination), (ushort)destinationPort)] = 1;
        }
        Console.WriteLine($"[Redirector] EXEMPT flow +{sourcePort} -> {destination}:{destinationPort}");
    }

    public void UnregisterFlowExemption(int sourcePort, IPAddress destination, int destinationPort)
    {
        var removed = destination.AddressFamily == AddressFamily.InterNetworkV6
            ? RemoveV6(sourcePort, destination, destinationPort)
            : _v4ExemptFlows.TryRemove(
                new V4ExemptKey((ushort)sourcePort, RawV4(destination), (ushort)destinationPort), out _);
        if (removed)
            Console.WriteLine($"[Redirector] EXEMPT flow -{sourcePort} -> {destination}:{destinationPort}");
    }

    private bool RemoveV6(int sourcePort, IPAddress destination, int destinationPort)
    {
        var (hi, lo) = RawV6(destination);
        return _v6ExemptFlows.TryRemove(
            new V6ExemptKey((ushort)sourcePort, hi, lo, (ushort)destinationPort), out _);
    }

    public void RegisterLocalService(int dstPort)
    {
        _localServicePorts[dstPort] = 1;
        Console.WriteLine($"[Redirector] LOCAL +{dstPort} ({_localServicePorts.Count} held)");
    }

    public Task StartAsync()
    {
        Console.WriteLine("[Redirector] Started");
        _ = Task.Run(() => CleanupLoop(_cts.Token));
        _runTask = Task.Run(() => Run(_local, _cts.Token));
        if (_lan != null)
            _lanTask = Task.Run(() => Run(_lan, _cts.Token));
        return Task.CompletedTask;
    }

    private void Run(Capture capture, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                unsafe { RunOnce(capture, ct); }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { Console.WriteLine($"[Redirector] Error: {ex.Message}"); }
        }
    }

    private unsafe void RunOnce(Capture capture, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        int recvLen;
        if (!capture.Handle.Recv((void*)capture.Packet, MTU_MAX, &recvLen, (Address*)capture.Addr))
            return;

        var version = (*(byte*)capture.Packet >> 4) & 0x0F;

        if (version == 4 && recvLen >= sizeof(NativeIpv4Header))
        {
            var ip4 = (NativeIpv4Header*)capture.Packet;
            // Only the first fragment carries the header whose ports name the flow, and rewriting a
            // datagram piece by piece cannot redo the upper-layer checksum, which covers the reassembled
            // segment and the addresses this rewrite changes. So a fragmented datagram goes through as it
            // came, whole, exactly as Router leaves it (RFC 791 §3.2 fragment offset, RFC 793 §3.1 the
            // checksum and its pseudo-header).
            if (ip4->Protocol == 6 && (NetToHost(ip4->FlagsAndFragOff) & 0x3FFF) != 0)
            {
                var frag = Interlocked.Increment(ref _fragPassed);
                if (frag <= 10)
                    Console.WriteLine($"[Redirector] PASS v4 fragment id={NetToHost(ip4->Id)} MF={(NetToHost(ip4->FlagsAndFragOff) >> 13) & 1}" +
                                      $" off={NetToHost(ip4->FlagsAndFragOff) & 0x1FFF}" +
                                      $" {new IPAddress(ip4->SrcAddr)}->{new IPAddress(ip4->DstAddr)}");
                capture.Handle.Send((void*)capture.Packet, recvLen, null, (Address*)capture.Addr);
                return;
            }
            if (ip4->Protocol == 6 && recvLen >= ip4->HeaderLength + sizeof(NativeTcpHeader))
            {
                var tcp = (NativeTcpHeader*)((byte*)capture.Packet + ip4->HeaderLength);
                ProcessV4(capture, recvLen, ip4, tcp);
            }
            else
            {
                capture.Handle.Send((void*)capture.Packet, recvLen, null, (Address*)capture.Addr);
            }
        }
        else if (version == 6 && recvLen >= sizeof(NativeIpv6Header))
        {
            var ip6 = (NativeIpv6Header*)capture.Packet;
            if (ip6->NextHeader == 6 && recvLen >= sizeof(NativeIpv6Header) + sizeof(NativeTcpHeader))
            {
                var tcp = (NativeTcpHeader*)((byte*)capture.Packet + sizeof(NativeIpv6Header));
                ProcessV6(capture, recvLen, ip6, tcp);
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
                capture.Handle.Send((void*)capture.Packet, recvLen, null, (Address*)capture.Addr);
            }
        }
        else
        {
            capture.Handle.Send((void*)capture.Packet, recvLen, null, (Address*)capture.Addr);
        }
    }

    private unsafe bool IsV6FlowExempt(int srcPort, NativeIpv6Header* ip6, int dstPort)
    {
        if (_v6ExemptFlows.IsEmpty) return false;
        var (hi, lo) = ReadV6(ip6->DestinationAddress);
        return _v6ExemptFlows.ContainsKey(new V6ExemptKey((ushort)srcPort, hi, lo, (ushort)dstPort));
    }

    private unsafe void ProcessV4(Capture capture, int recvLen, NativeIpv4Header* ip4, NativeTcpHeader* tcp)
    {
        var srcPort = NetToHost(tcp->SrcPort);
        var dstPort = NetToHost(tcp->DstPort);

        if (_exemptPorts.ContainsKey(srcPort)
            || _v4ExemptFlows.ContainsKey(new V4ExemptKey((ushort)srcPort, ip4->DstAddr, (ushort)dstPort)))
        {
            capture.Handle.Send((void*)capture.Packet, recvLen, null, (Address*)capture.Addr);
            return;
        }

        // Loopback is in the condition so this stays "traffic to our own endpoint", never a
        // destination-port exclusion that would let a real server on 8873 through unmitm'd.
        if (IsIPv4Loopback(ip4->DstAddr) && _localServicePorts.ContainsKey(dstPort))
        {
            capture.Handle.Send((void*)capture.Packet, recvLen, null, (Address*)capture.Addr);
            return;
        }

        var isSyn = (tcp->Flags & TcpFlag.Syn) != 0 && (tcp->Flags & TcpFlag.Ack) == 0;
        var isFinOrRst = (tcp->Flags & (TcpFlag.Fin | TcpFlag.Rst)) != 0;

        if (srcPort == _relayPort)
            ReverseSwapV4(capture, recvLen, ip4, tcp, dstPort, isFinOrRst);
        else if (dstPort != _relayPort)
            ForwardSwapV4(capture, recvLen, ip4, tcp, srcPort, dstPort, isSyn, isFinOrRst);
        else
            capture.Handle.Send((void*)capture.Packet, recvLen, null, (Address*)capture.Addr);
    }

    private unsafe void ForwardSwapV4(Capture capture, int recvLen, NativeIpv4Header* ip4, NativeTcpHeader* tcp,
        int srcPort, int dstPort, bool isSyn, bool isFinOrRst)
    {
        var srcAddr = ip4->SrcAddr;
        var dstAddr = ip4->DstAddr;
        // The address the accepted socket will report as its own: for a client on this machine that is
        // the client itself, and for a forwarded one it is this host's address on the LAN side, because
        // a client that is not on this machine cannot be the destination of a local socket.
        var localEndpoint = capture.Lan?.RawAddress ?? srcAddr;
        var key = FlowTable.KeyV4(srcAddr, (ushort)srcPort, dstAddr, (ushort)dstPort);
        var isLoopback = IsIPv4Loopback(srcAddr) && IsIPv4Loopback(dstAddr);

        if (isSyn)
        {
            var clientIp = new IPAddress(srcAddr);
            var destination = new IPAddress(dstAddr);
            // A pid scope names processes on this machine, and a forwarded client has none - and the
            // packet cannot be handed back for anyone else to route either, because a reinjection is
            // impostor and the forward handle below this one excludes impostor. So the flow stays
            // intercepted instead of becoming a bypass nothing downstream can pick up.
            if (capture.Lan == null && _filter is { IsActive: true } filter
                && !filter.Allows(clientIp, srcPort, out var identity))
            {
                // The scope decision has to be made here, not in the proxy: by the time a socket is
                // accepted the packet has already been swapped and the client is talking to us.
                _flows.Open(key, intercept: false);
                Console.WriteLine($"[Redirector] SCOPE pass v4 {clientIp}:{srcPort} -> {destination}:{dstPort} ({identity.Label})");
                capture.Handle.Send((void*)capture.Packet, recvLen, null, (Address*)capture.Addr);
                return;
            }
            var opened = _flows.Open(key, intercept: true);
            Console.WriteLine($"[Redirector] NEW v4 {clientIp}:{srcPort} -> {destination}:{dstPort} token={opened.Token}" +
                              (capture.Lan is { } side ? $" (forwarded, delivered to {side.Address})" : "") +
                              (opened.Bypassed ? " (pool full, passed through)" : ""));
        }

        if (_flows.Follow(key) is not { } entry)
        {
            var fwdMiss = Interlocked.Increment(ref _forwardMiss);
            if (fwdMiss <= 30)
                Console.WriteLine($"[Redirector] Fwd v4 MISS key={srcPort} {new IPAddress(srcAddr)}:{srcPort} -> {new IPAddress(dstAddr)}:{dstPort} flags={tcp->Flags}");
            capture.Handle.Send((void*)capture.Packet, recvLen, null, (Address*)capture.Addr);
            return;
        }

        if (entry.Bypassed)
        {
            entry.LastSeen = DateTime.UtcNow;
            capture.Handle.Send((void*)capture.Packet, recvLen, null, (Address*)capture.Addr);
            return;
        }

        entry.LastSeen = DateTime.UtcNow;

        // The token replaces the client's own source port on the way in, so the accepted socket carries
        // a number that names exactly one connection. The client never sees it: the reply leg puts its
        // real port back.
        tcp->SrcPort = HostToNet(entry.Token);
        tcp->DstPort = HostToNet((ushort)_relayPort);

        var addr = (Address*)capture.Addr;
        var calcOk = false;
        var routeErr = 0;
        var arrivedIfIdx = addr->IfIdx;
        var arrivedSubIfIdx = addr->SubIfIdx;
        if (!isLoopback)
        {
            ip4->SrcAddr = dstAddr;
            ip4->DstAddr = localEndpoint;
            // Which way an injected packet goes is this field alone, not the addresses inside it, and
            // this one is now addressed to this host.
            addr->Flags &= ~AddressFlag.Outbound;
            if (capture.Lan is { } lan)
            {
                // A forwarded packet arrives carrying the egress interface. Receive is strong-host on
                // this machine - WeakHostReceive reads Disabled on every interface - so a datagram that
                // arrives on one interface addressed to another's address is discarded (RFC 1122
                // §3.3.4.2), and the index has to name the interface that owns the destination.
                addr->IfIdx = lan.IfIdx;
                // SubIfIdx is the sub-interface *within* that index and is not a second copy of it:
                // leaving the arrival value is the only reading the driver itself uses, and
                // tools/inject reads this field off a real arriving packet rather than guessing it.
                // Measured: with the interface index copied into it (30/30) no forwarded SYN ever
                // reached the relay socket, while the arrival value (30/0) is accepted at once.
            }
            else
            {
                // The index a local packet came with already owns its client's address, so only the
                // direction is in question; the lookup reports what the routing table says about it.
                calcOk = _local.Handle.CalcOutboundFlag((void*)capture.Packet, addr, out routeErr);
            }
        }

        _local.Handle.CalcChecksums((void*)capture.Packet, recvLen, addr);
        var sent = _local.Handle.Send((void*)capture.Packet, recvLen, null, addr);
        if (isSyn && !isLoopback)
            Console.WriteLine($"[Redirector] Fwd v4 {new IPAddress(srcAddr)}:{srcPort}->{new IPAddress(dstAddr)}:{dstPort}" +
                              $" to {new IPAddress(localEndpoint)} ifIdx={addr->IfIdx}/{addr->SubIfIdx}" +
                              $" (arrived {arrivedIfIdx}/{arrivedSubIfIdx}) calc={calcOk}" +
                              $" routeErr={routeErr} flags={addr->Flags} sent={sent}");

        if (isFinOrRst)
        {
            // Keep translating after a FIN/RST: the peer still owes ACKs, and releasing the
            // proxy's reply to the real server makes it answer with an RST onto the live client socket.
            entry.Closing = true;
        }
    }

    private unsafe void ReverseSwapV4(Capture capture, int recvLen, NativeIpv4Header* ip4, NativeTcpHeader* tcp,
        int dstPort, bool isFinOrRst)
    {
        var srcAddr = ip4->SrcAddr;
        var dstAddr = ip4->DstAddr;

        if (_flows.ByToken((ushort)dstPort) is not { } conn)
        {
            var miss = Interlocked.Increment(ref _reverseMiss);
            if (miss <= 200)
                Console.WriteLine($"[Redirector] Rev v4 MISS token={dstPort} flags={tcp->Flags} (relay<->{new IPAddress(dstAddr)})");
            capture.Handle.Send((void*)capture.Packet, recvLen, null, (Address*)capture.Addr);
            return;
        }

        conn.LastSeen = DateTime.UtcNow;

        var isLoopback = IsIPv4Loopback(srcAddr) && IsIPv4Loopback(dstAddr);

        if (!isLoopback)
        {
            ip4->SrcAddr = dstAddr;
            // The client's own address rather than the local endpoint: a forwarded flow has to go back
            // out to the client, while its local endpoint was this host.
            ip4->DstAddr = conn.ClientRaw;
        }

        // Both ports come from the state now: the one the proxy answered is the token, and the client
        // has to see the pair it sent.
        tcp->SrcPort = HostToNet((ushort)conn.OrigDstPort);
        tcp->DstPort = HostToNet((ushort)conn.ClientPort);

        _local.Handle.CalcChecksums((void*)capture.Packet, recvLen, (Address*)capture.Addr);
        var sent = _local.Handle.Send((void*)capture.Packet, recvLen, null, (Address*)capture.Addr);
        conn.RevCount++;
        if (conn.RevCount <= 3)
            Console.WriteLine($"[Redirector] Rev v4 k={dstPort} n={conn.RevCount} {conn.ClientAddr}:{conn.ClientPort}" +
                              $" -> {conn.OrigDstAddr}:{conn.OrigDstPort} loopback={isLoopback} flags={tcp->Flags} sent={sent}");

        if (isFinOrRst)
        {
            conn.Closing = true;
            // The line the n<=3 window above never reaches: this is our close leaving for the client, which
            // is what the closing clock a released flow hands over to exists to carry.
            Console.WriteLine($"[Redirector] Rev v4 k={dstPort} closing {conn.ClientAddr}:{conn.ClientPort}" +
                              $" -> {conn.OrigDstAddr}:{conn.OrigDstPort} flags={tcp->Flags}");
        }
    }

    private unsafe void ProcessV6(Capture capture, int recvLen, NativeIpv6Header* ip6, NativeTcpHeader* tcp)
    {
        var srcPort = NetToHost(tcp->SrcPort);
        var dstPort = NetToHost(tcp->DstPort);

        if (_exemptPorts.ContainsKey(srcPort) || IsV6FlowExempt(srcPort, ip6, dstPort))
        {
            capture.Handle.Send((void*)capture.Packet, recvLen, null, (Address*)capture.Addr);
            return;
        }

        if (IsIPv6Loopback(ip6->DestinationAddress) && _localServicePorts.ContainsKey(dstPort))
        {
            capture.Handle.Send((void*)capture.Packet, recvLen, null, (Address*)capture.Addr);
            return;
        }

        var isSyn = (tcp->Flags & TcpFlag.Syn) != 0 && (tcp->Flags & TcpFlag.Ack) == 0;
        var isFinOrRst = (tcp->Flags & (TcpFlag.Fin | TcpFlag.Rst)) != 0;

        if (srcPort == _relayPort)
            ReverseSwapV6(capture, recvLen, ip6, tcp, dstPort, isFinOrRst);
        else if (dstPort != _relayPort)
            ForwardSwapV6(capture, recvLen, ip6, tcp, srcPort, dstPort, isSyn, isFinOrRst);
        else
            capture.Handle.Send((void*)capture.Packet, recvLen, null, (Address*)capture.Addr);
    }

    private unsafe void ForwardSwapV6(Capture capture, int recvLen, NativeIpv6Header* ip6, NativeTcpHeader* tcp,
        int srcPort, int dstPort, bool isSyn, bool isFinOrRst)
    {
        var (srcHi, srcLo) = ReadV6(ip6->SourceAddress);
        var (dstHi, dstLo) = ReadV6(ip6->DestinationAddress);
        var isLoopback = IsIPv6Loopback(ip6->SourceAddress) && IsIPv6Loopback(ip6->DestinationAddress);
        var key = FlowTable.KeyV6(srcHi, srcLo, (ushort)srcPort, dstHi, dstLo, (ushort)dstPort);

        if (isSyn)
        {
            var srcAddr = new IPAddress(FlowState.RawV6Bytes(srcHi, srcLo));
            var dstAddr = new IPAddress(FlowState.RawV6Bytes(dstHi, dstLo));
            if (_filter is { IsActive: true } filter && !filter.Allows(srcAddr, srcPort, out var identity))
            {
                _flows.Open(key, intercept: false);
                Console.WriteLine($"[Redirector] SCOPE pass v6 {srcAddr}:{srcPort} -> {dstAddr}:{dstPort} ({identity.Label})");
                capture.Handle.Send((void*)capture.Packet, recvLen, null, (Address*)capture.Addr);
                return;
            }
            var opened = _flows.Open(key, intercept: true);
            Console.WriteLine($"[Redirector] NEW v6 {srcAddr}:{srcPort} -> {dstAddr}:{dstPort} token={opened.Token}" +
                              (opened.Bypassed ? " (pool full, passed through)" : ""));
        }

        if (_flows.Follow(key) is not { } entry)
        {
            var v6Miss = Interlocked.Increment(ref _forwardMiss);
            if (v6Miss <= 30)
                Console.WriteLine($"[Redirector] Fwd v6 MISS key={srcPort} {new IPAddress(FlowState.RawV6Bytes(srcHi, srcLo))}:{srcPort}" +
                                  $" -> {new IPAddress(FlowState.RawV6Bytes(dstHi, dstLo))}:{dstPort} flags={tcp->Flags}");
            capture.Handle.Send((void*)capture.Packet, recvLen, null, (Address*)capture.Addr);
            return;
        }

        if (entry.Bypassed)
        {
            entry.LastSeen = DateTime.UtcNow;
            capture.Handle.Send((void*)capture.Packet, recvLen, null, (Address*)capture.Addr);
            return;
        }

        entry.LastSeen = DateTime.UtcNow;

        tcp->SrcPort = HostToNet(entry.Token);
        tcp->DstPort = HostToNet((ushort)_relayPort);

        if (!isLoopback)
        {
            WriteV6(ip6->SourceAddress, dstHi, dstLo);
            WriteV6(ip6->DestinationAddress, srcHi, srcLo);
            ((Address*)capture.Addr)->Flags &= ~AddressFlag.Outbound;
            _local.Handle.CalcOutboundFlag((void*)capture.Packet, (Address*)capture.Addr);
        }

        _local.Handle.CalcChecksums((void*)capture.Packet, recvLen, (Address*)capture.Addr);
        _local.Handle.Send((void*)capture.Packet, recvLen, null, (Address*)capture.Addr);

        if (isFinOrRst)
            entry.Closing = true;
    }

    private unsafe void ReverseSwapV6(Capture capture, int recvLen, NativeIpv6Header* ip6, NativeTcpHeader* tcp,
        int dstPort, bool isFinOrRst)
    {
        var isLoopback = IsIPv6Loopback(ip6->SourceAddress) && IsIPv6Loopback(ip6->DestinationAddress);

        if (_flows.ByToken((ushort)dstPort) is not { } conn)
        {
            var miss6 = Interlocked.Increment(ref _reverseMiss);
            if (miss6 <= 200)
                Console.WriteLine($"[Redirector] Rev v6 MISS token={dstPort} flags={tcp->Flags}");
            capture.Handle.Send((void*)capture.Packet, recvLen, null, (Address*)capture.Addr);
            return;
        }

        conn.LastSeen = DateTime.UtcNow;

        // The addresses come from the flow's own key rather than from the packet, because the packet
        // only carries the local endpoint this host answered on.
        if (!isLoopback)
        {
            WriteV6(ip6->SourceAddress, conn.Key.ServerHi, conn.Key.ServerLo);
            WriteV6(ip6->DestinationAddress, conn.Key.ClientHi, conn.Key.ClientLo);
        }

        tcp->SrcPort = HostToNet((ushort)conn.OrigDstPort);
        tcp->DstPort = HostToNet((ushort)conn.ClientPort);

        _local.Handle.CalcChecksums((void*)capture.Packet, recvLen, (Address*)capture.Addr);
        _local.Handle.Send((void*)capture.Packet, recvLen, null, (Address*)capture.Addr);

        if (isFinOrRst)
        {
            conn.Closing = true;
            Console.WriteLine($"[Redirector] Rev v6 k={dstPort} closing {conn.ClientAddr}:{conn.ClientPort}" +
                              $" -> {conn.OrigDstAddr}:{conn.OrigDstPort} flags={tcp->Flags}");
        }
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

    private static unsafe bool IsIPv6Loopback(byte* addr)
    {
        for (int i = 0; i < 15; i++)
            if (addr[i] != 0) return false;
        return addr[15] == 1;
    }

    private async Task CleanupLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromSeconds(5), ct);
            foreach (var state in _flows.Sweep())
                Console.WriteLine($"[Redirector] DROP {(state.Key.V6 ? "v6" : "v4")} token={state.Token}" +
                                  $" {state.ClientAddr}:{state.ClientPort} -> {state.OrigDstAddr}:{state.OrigDstPort}" +
                                  $" reason={(state.Closing ? "closed" : state.Session ? "session stale" : "idle")}" +
                                  $" rev={state.RevCount}");
        }
    }


    private readonly record struct V4ExemptKey(ushort SrcPort, uint DstIp, ushort DstPort);

    private readonly record struct V6ExemptKey(ushort SrcPort, ulong DstHi, ulong DstLo, ushort DstPort);

    public void Dispose()
    {
        // `using var` is the only caller today, but exiting during shutdown raced a second pass here
        // once: the guard costs one interlocked op and makes any future explicit call safe.
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _cts.Cancel();
        _local.Handle.Shutdown();
        _lan?.Handle.Shutdown();
        _runTask?.Wait(TimeSpan.FromSeconds(2));
        _lanTask?.Wait(TimeSpan.FromSeconds(2));
        _local.Dispose();
        _lan?.Dispose();
        _cts.Dispose();
    }

    // One handle and its own receive buffers. Two loops sharing one buffer pair would be two threads
    // rewriting each other's packet, so the buffers belong to the leg that fills them.
    private sealed class Capture : IDisposable
    {
        public readonly WinDivertHandle Handle;
        public readonly IntPtr Packet;
        public readonly IntPtr Addr;
        public readonly LanSide? Lan;

        public Capture(WinDivertHandle handle, LanSide? lan)
        {
            Handle = handle;
            Lan = lan;
            Packet = Marshal.AllocHGlobal(MTU_MAX);
            Addr = Marshal.AllocHGlobal(ADDR_SIZE);
            unsafe
            {
                new Span<byte>((void*)Packet, MTU_MAX).Clear();
                new Span<byte>((void*)Addr, ADDR_SIZE).Clear();
            }
        }

        public void Dispose()
        {
            Handle.Dispose();
            Marshal.FreeHGlobal(Packet);
            Marshal.FreeHGlobal(Addr);
        }
    }
}
