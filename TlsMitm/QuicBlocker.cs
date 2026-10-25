using System.Runtime.InteropServices;
using static TlsMitm.WinDivertPInvoke;

namespace TlsMitm;

public class QuicBlocker : IDisposable
{
    private readonly WinDivertHandle _divert;
    private readonly CancellationTokenSource _cts = new();
    private Task? _runTask;
    private long _blockedCount;
    private int _disposed;
    private readonly IntPtr _pPacket;
    private readonly IntPtr _pAddr;

    public QuicBlocker()
    {
        _divert = new WinDivertHandle("udp and outbound");
        _pPacket = Marshal.AllocHGlobal(MTU_MAX);
        _pAddr = Marshal.AllocHGlobal(ADDR_SIZE);
        unsafe
        {
            new Span<byte>((void*)_pPacket, MTU_MAX).Clear();
            new Span<byte>((void*)_pAddr, ADDR_SIZE).Clear();
        }
        Console.WriteLine("[QuicBlocker] Filter: udp and outbound");
        Console.WriteLine("[QuicBlocker] Will detect QUIC by protocol signature on ANY port");
    }

    public Task StartAsync()
    {
        _runTask = Task.Run(() => RunAsync(_cts.Token));
        Console.WriteLine("[QuicBlocker] Started");
        return Task.CompletedTask;
    }

    private Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                unsafe { RunOnce(ct); }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { Console.WriteLine($"[QuicBlocker] Error: {ex.Message}"); }
        }
        return Task.CompletedTask;
    }

    private unsafe void RunOnce(CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        int recvLen;
        if (!_divert.Recv((void*)_pPacket, MTU_MAX, &recvLen, (Address*)_pAddr))
            return;

        var ip4 = (NativeIpv4Header*)_pPacket;
        if (ip4->Version == 4 && ip4->Protocol == 17)
        {
            var udp = (NativeUdpHeader*)((byte*)_pPacket + ip4->HeaderLength);
            var payload = (byte*)udp + sizeof(NativeUdpHeader);
            var payloadLen = recvLen - ip4->HeaderLength - sizeof(NativeUdpHeader);

            if (payloadLen >= 6 && IsQuicPacket(payload, payloadLen))
            {
                var count = Interlocked.Increment(ref _blockedCount);
                if (count <= 10 || count % 100 == 0)
                    Console.WriteLine($"[QuicBlocker] Blocked QUIC packet to port {NetToHost(udp->DstPort)} (total: {count})");
                return;
            }
        }
        else if (recvLen >= sizeof(NativeIpv6Header))
        {
            var ip6 = (NativeIpv6Header*)_pPacket;
            if (ip6->NextHeader == 17)
            {
                var udp = (NativeUdpHeader*)((byte*)_pPacket + sizeof(NativeIpv6Header));
                var payload = (byte*)udp + sizeof(NativeUdpHeader);
                var payloadLen = recvLen - sizeof(NativeIpv6Header) - sizeof(NativeUdpHeader);

                if (payloadLen >= 6 && IsQuicPacket(payload, payloadLen))
                {
                    var count = Interlocked.Increment(ref _blockedCount);
                    if (count <= 10 || count % 100 == 0)
                        Console.WriteLine($"[QuicBlocker] Blocked QUIC packet to port {NetToHost(udp->DstPort)} (total: {count})");
                    return;
                }
            }
        }

        _divert.Send((void*)_pPacket, recvLen, null, (Address*)_pAddr);
    }

    private static unsafe bool IsQuicPacket(byte* payload, int payloadLen)
    {
        if (payloadLen < 6) return false;

        var b0 = payload[0];
        var b1 = payload[1];

        if ((b0 & 0xC0) == 0xC0 && (b1 & 0x80) != 0)
        {
            var version = (uint)((payload[2] << 24) | (payload[3] << 16) | (payload[4] << 8) | payload[5]);

            if (version == 0x00000001 || version == 0x6b3343cf || version == 0x00000000)
                return true;

            if (payload[2] == 0x51) // 'Q' (Google QUIC)
                return true;
        }

        return false;
    }

    public void Dispose()
    {
        // Same double-dispose path as PacketRedirector: explicit call in Program.cs plus `using var`.
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _cts.Cancel();
        _divert.Shutdown();
        _runTask?.Wait(TimeSpan.FromSeconds(2));
        _divert.Dispose();
        Marshal.FreeHGlobal(_pPacket);
        Marshal.FreeHGlobal(_pAddr);
        _cts.Dispose();
        Console.WriteLine($"[QuicBlocker] Stopped (blocked {Interlocked.Read(ref _blockedCount)} QUIC packets total)");
    }
}
