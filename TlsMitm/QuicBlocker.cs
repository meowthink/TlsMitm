using System.Runtime.InteropServices;
using static TlsMitm.WinDivertPInvoke;

namespace TlsMitm;

public class QuicBlocker : IDisposable
{
    // One capture point: a handle, its own buffers (the two legs run on their own threads and cannot
    // share them), and the count of what it dropped.
    private sealed class Leg : IDisposable
    {
        public readonly WinDivertHandle Handle;
        public readonly IntPtr Packet;
        public readonly IntPtr Addr;
        public readonly string Name;
        public long Seen;
        public long Blocked;

        public unsafe Leg(WinDivertHandle handle, string name)
        {
            Handle = handle;
            Name = name;
            Packet = Marshal.AllocHGlobal(MTU_MAX);
            Addr = Marshal.AllocHGlobal(ADDR_SIZE);
            new Span<byte>((void*)Packet, MTU_MAX).Clear();
            new Span<byte>((void*)Addr, ADDR_SIZE).Clear();
        }

        public void Dispose()
        {
            Handle.Dispose();
            Marshal.FreeHGlobal(Packet);
            Marshal.FreeHGlobal(Addr);
        }
    }

    private readonly Leg _local;
    private readonly Leg? _forwarded;
    private readonly CancellationTokenSource _cts = new();
    private Task? _runTask;
    private Task? _forwardedTask;
    private int _disposed;

    public QuicBlocker(LanSide? lan = null)
    {
        _local = new Leg(new WinDivertHandle("udp and outbound"), "local");
        Console.WriteLine("[QuicBlocker] Filter: udp and outbound");
        Console.WriteLine("[QuicBlocker] Will detect QUIC by protocol signature on ANY port");
        if (lan != null)
        {
            // A LAN client's QUIC is routed, not sent by this host, so the outbound network-layer
            // capture above never sees it. Reinjecting what is not QUIC hands it to the lower-priority
            // handles, which is how ordinary UDP still reaches Router.
            _forwarded = new Leg(new WinDivertHandle(lan.UdpFilter, Layer.Forward), "forwarded");
            Console.WriteLine($"[QuicBlocker] LAN filter: {lan.UdpFilter}");
        }
    }

    public Task StartAsync()
    {
        _runTask = Task.Run(() => RunAsync(_local, _cts.Token));
        _forwardedTask = _forwarded == null ? null : Task.Run(() => RunAsync(_forwarded, _cts.Token));
        Console.WriteLine("[QuicBlocker] Started");
        return Task.CompletedTask;
    }

    private Task RunAsync(Leg leg, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                unsafe { RunOnce(leg); }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { Console.WriteLine($"[QuicBlocker] Error: {ex.Message}"); }
        }
        return Task.CompletedTask;
    }

    private unsafe void RunOnce(Leg leg)
    {
        if (_cts.IsCancellationRequested) return;

        int recvLen;
        if (!leg.Handle.Recv((void*)leg.Packet, MTU_MAX, &recvLen, (Address*)leg.Addr))
            return;

        Interlocked.Increment(ref leg.Seen);
        if (QuicSignature.IsQuicDatagram((byte*)leg.Packet, recvLen, out var dstPort))
        {
            var count = Interlocked.Increment(ref leg.Blocked);
            if (count <= 10 || count % 100 == 0)
                Console.WriteLine($"[QuicBlocker] Blocked {leg.Name} QUIC packet to port {dstPort} (total: {count})");
            return;
        }

        leg.Handle.Send((void*)leg.Packet, recvLen, null, (Address*)leg.Addr);
    }

    public void Dispose()
    {
        // Same double-dispose guard as PacketRedirector: harmless now, and it keeps a future explicit
        // call from cancelling a disposed CTS and freeing the same native buffers twice.
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _cts.Cancel();
        _local.Handle.Shutdown();
        _forwarded?.Handle.Shutdown();
        _runTask?.Wait(TimeSpan.FromSeconds(2));
        _forwardedTask?.Wait(TimeSpan.FromSeconds(2));
        var blockedLocal = Interlocked.Read(ref _local.Blocked);
        var blockedForwarded = _forwarded == null ? 0 : Interlocked.Read(ref _forwarded.Blocked);
        var seenLocal = Interlocked.Read(ref _local.Seen);
        var seenForwarded = _forwarded == null ? 0 : Interlocked.Read(ref _forwarded.Seen);
        _local.Dispose();
        _forwarded?.Dispose();
        _cts.Dispose();
        // The seen counts are printed beside the blocked ones because a leg that saw no datagram and a
        // leg that saw only non-QUIC ones otherwise end with the same "blocked 0".
        Console.WriteLine($"[QuicBlocker] Stopped (blocked {blockedLocal} of {seenLocal} local and " +
                          $"{blockedForwarded} of {seenForwarded} forwarded UDP datagrams as QUIC)");
    }
}
