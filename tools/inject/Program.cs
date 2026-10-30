using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;
using static TlsMitm.WinDivertPInvoke;

// A substitute LAN client, so one question can be asked of Router without a phone in the loop: does a
// packet that arrives inbound on the LAN interface, from a LAN address to an off-link address, get
// source-NATed and forwarded?
//
// --filter hands the driver expression to every handle, which is how this program is pointed at anything
// other than TCP/UDP/ICMPv4. The pair accounting here is IPv4's alone - it reads an IPv4 header - so an
// IPv6 filter turns the readers into an observer instead: each IPv6 packet prints its addresses, its
// ICMPv6 type and, for NS/NA, the target, and is counted as not-IPv4 rather than folded into counts that
// would then mean two things.
//
// Three vantage points, because the diversion order decides what each one can see. Higher priority values
// are handled first, a packet injected by a handle is offered only to the handles below it, and a priority
// orders the handles of one layer only - upstream defines two capture points, Layer.Network as "network
// packets to/from the local machine" and Layer.Forward as "network packets passing through" it, and a
// router lives on the second:
//   pre  (+150, Layer.Network)  this host's own traffic, ahead of anything else. Measured here, not
//          assumed: an injection sent from +200 returned no error and never reappeared at +150, so an
//          injected packet is not evidence that a real client's packet arrived - the --any view is.
//   post (-200, Layer.Network)  the same view below the injection, for whatever the stack makes of it.
//   fwd  (--fwd, Layer.Forward) two readers, one at +150 and one at -200, because Router is at -100: the
//          first is offered a transit packet as Router is, the second sees what Router puts back, if it
//          puts anything back. Neither a client's transit packet nor a rewrite of it ever appears at
//          Layer.Network, which is the reason this pair exists.
//
// Injection uses the mechanism the WinDivertSend remarks document: on the network layer the address's
// Outbound bit chooses the path, and for Outbound = 0 the IfIdx and SubIfIdx in the address are the
// interface the packet arrived on. Impostor is left clear, because Router's filter asks for
// "not impostor" and would otherwise walk past it.
//
// Every handle is opened with Sniff, so none of them can take a packet off the stack: this program
// observes and injects, and leaves the traffic it is measuring alone.

const byte DefaultTtl = 64;
// 150 rather than 100 because a packet is diverted once per priority level and Router's own --trace
// handle sits at 100: two handles at one level leave it undefined which one sees the packet.
const int PrePriority = 150;
// Below Router's -100 on purpose: a packet a handle injects is offered to the handles under it, so this
// is the only vantage from which a reinjection is visible.
const int PostPriority = -200;
const int SendPriority = 200;
// Enough to show the shapes and the first flows, short enough that a client's burst of hundreds of
// packets does not turn the console into a wall. Counting carries on past it.
const int PrintCap = 20;

string? Option(string name)
{
    var index = Array.IndexOf(args, name);
    return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
}

var showAny = Array.IndexOf(args, "--any") >= 0;
var showFwd = Array.IndexOf(args, "--fwd") >= 0;

if (args.Length == 0 || Option("--help") is not null || Option("--ifidx") is null || (Option("--dst") is null && !showAny))
{
    Console.WriteLine("usage: inject --ifidx <n> [--dst <ipv4>] [--subifidx <n>] [--src <ipv4>] [--fwd] [--any]");
    Console.WriteLine("             [--proto icmp|udp|tcp] [--sport <n>] [--dport <n>] [--ttl <n>]");
    Console.WriteLine($"             [--count <n>] [--interval-ms <n>] [--calibrate <sec>] [--watch <sec>]   (default --ttl {DefaultTtl})");
    Console.WriteLine("             [--filter <winDivert expression>]");
    Console.WriteLine("--any is the one mode that runs without --dst: it watches an interface rather than a pair,");
    Console.WriteLine("which is also what an IPv6 filter needs, since no IPv4 address can name those packets.");
    Console.WriteLine("--filter replaces the default 'tcp or udp or icmp' on every handle. An IPv6 expression");
    Console.WriteLine($"such as 'ipv6 and icmpv6' makes the pre reader print each IPv6 packet (first {PrintCap}) with its");
    Console.WriteLine("interfaces, its ICMPv6 type and, for NS/NA, the target address; those packets are outside the");
    Console.WriteLine("IPv4 tallies below.");
    Console.WriteLine("--count 0 injects nothing and leaves the two readers running, which is the way to");
    Console.WriteLine("watch a real client's packet cross both vantage points.");
    Console.WriteLine("--any prints every packet on --ifidx in either direction, not just the --src/--dst");
    Console.WriteLine("pair, and ends with a tally of where --src sent and who answered it: the question it");
    Console.WriteLine("answers is what the client really addresses, which a pair-filtered view cannot");
    Console.WriteLine("distinguish from silence.");
    Console.WriteLine("--fwd adds two readers on Layer.Forward, the capture point a packet that this host");
    Console.WriteLine("routes rather than delivers is seen at, one above Router's priority and one below it:");
    Console.WriteLine("the first is offered the client's packet as Router is, the second sees what Router");
    Console.WriteLine("puts back. Each prints the first 20 packets and then only counts, and ends with the");
    Console.WriteLine("address shapes it saw - the interface a transit packet is tagged with is what a");
    Console.WriteLine("rewrite has to be written against.");
    Console.WriteLine("an injected --src defaults to the address a leased client holds, so a reply has a");
    Console.WriteLine("chance of being routed back to it; --subifidx is required unless a real inbound");
    Console.WriteLine("packet is heard on --ifidx during --calibrate, because the sub-interface index is");
    Console.WriteLine("part of what says which interface a packet arrived on and a guessed one is not a");
    Console.WriteLine("fact the measurement should rest on.");
    return 1;
}

// Absent under --any, where nothing is measured against a pair: a zero here matches no packet, so the
// pair branches stay inert while the readers and the arrival counts keep working.
var dst = Option("--dst") is { } dstText ? ParseAddress("--dst", dstText) : 0u;
var src = ParseAddress("--src", Option("--src") ?? "192.168.122.100");
var ifIdx = Number("--ifidx", Option("--ifidx")!);
var filter = Option("--filter") ?? "tcp or udp or icmp";
var protoName = Option("--proto") ?? "icmp";
if (protoName is not ("icmp" or "udp" or "tcp"))
{
    Console.WriteLine($"[inject] --proto {protoName}: the packet has to be one this program can carry, icmp, udp or tcp.");
    return 1;
}
var proto = protoName switch { "icmp" => (byte)1, "udp" => (byte)17, _ => (byte)6 };
var ttl = (byte)Number("--ttl", Option("--ttl") ?? DefaultTtl.ToString());
var count = Number("--count", Option("--count") ?? "1");
var intervalMs = Number("--interval-ms", Option("--interval-ms") ?? "1000");
var calibrateSec = Number("--calibrate", Option("--calibrate") ?? "5");
var watchSec = Number("--watch", Option("--watch") ?? "5");
var sport = (ushort)Number("--sport", Option("--sport") ?? (proto == 1 ? "4660" : "40000"));
var dport = (ushort)Number("--dport", Option("--dport") ?? proto switch { 17 => "53", 6 => "443", _ => "0" });

var state = new State();
var transit = new State();
var transitBelow = new State();
WinDivertHandle sender;
WinDivertHandle pre;
WinDivertHandle post;
try
{
    sender = new WinDivertHandle(filter, Layer.Network, SendPriority, Flag.Sniff | Flag.SendOnly);
    pre = new WinDivertHandle(filter, Layer.Network, PrePriority, Flag.Sniff | Flag.RecvOnly);
    post = new WinDivertHandle(filter, Layer.Network, PostPriority, Flag.Sniff | Flag.RecvOnly);
}
catch (Exception ex)
{
    Console.WriteLine($"[inject] WinDivertOpen failed: {ex.Message}");
    Console.WriteLine("[inject] Needs elevation - the driver is loaded on open.");
    return 1;
}

// Opened after the two network-layer handles and with its own failure report, because whether the driver
// takes a forward-layer handle at all is one of the answers being looked for, and losing the network-layer
// observation over it would throw away the half of the comparison that already works.
WinDivertHandle? fwd = null;
WinDivertHandle? fwdBelow = null;
if (showFwd)
{
    try
    {
        // Two readers, one above Router's -100 and one below it: a packet a handle injects is offered only
        // to the handles beneath it, so the first sees the client's packet exactly as Router is asked about
        // it and the second sees whatever Router puts back, with the flags that come with it.
        fwd = new WinDivertHandle(filter, Layer.Forward, PrePriority, Flag.Sniff | Flag.RecvOnly);
        fwdBelow = new WinDivertHandle(filter, Layer.Forward, PostPriority, Flag.Sniff | Flag.RecvOnly);
        Console.WriteLine("[inject] Layer.Forward handles opened, one above and one below Router's priority");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[inject] Layer.Forward handle refused: {ex.Message}");
    }
}

using (sender)
using (pre)
using (post)
{
    var preReader = new Thread(() => ReadLoop(pre, "pre ", ifIdx, src, dst, state, calibrate: true, showAny));
    var postReader = new Thread(() => ReadLoop(post, "post", ifIdx, src, dst, state, calibrate: false, showAny));
    preReader.IsBackground = true;
    postReader.IsBackground = true;
    preReader.Start();
    postReader.Start();
    Thread? fwdReader = null;
    Thread? fwdBelowReader = null;
    if (fwd is { } forward)
    {
        fwdReader = new Thread(() => TransitLoop(forward, src, dst, transit, "above"));
        fwdReader.IsBackground = true;
        fwdReader.Start();
    }
    if (fwdBelow is { } below)
    {
        fwdBelowReader = new Thread(() => TransitLoop(below, src, dst, transitBelow, "below"));
        fwdBelowReader.IsBackground = true;
        fwdBelowReader.Start();
    }

    int? subIfIdx = Option("--subifidx") is { } given ? Number("--subifidx", given) : null;
    if (subIfIdx is null && count > 0)
    {
        Console.WriteLine($"[inject] listening up to {calibrateSec}s for a real inbound packet on ifIdx {ifIdx} to read its subIfIdx");
        var deadline = Environment.TickCount64 + calibrateSec * 1000L;
        while (Environment.TickCount64 < deadline && state.SubIfIdx is null)
            Thread.Sleep(100);
        subIfIdx = state.SubIfIdx;
        if (subIfIdx is null)
        {
            Console.WriteLine($"[inject] nothing arrived inbound on ifIdx {ifIdx}; pass --subifidx <n>.");
            state.Stop = true;
            return 1;
        }
        Console.WriteLine($"[inject] subIfIdx={subIfIdx} read from a packet that really arrived there");
    }

    // --count 0 asks nothing of the injection path and leaves this a pure observer, which is the
    // instrument for a client's own packet: whether a handle's injection is offered to the handles
    // below it is driver behaviour this program cannot settle, and a packet that really arrived is not
    // subject to the question.
    var injected = 0;
    if (count > 0)
    {
        var packet = BuildPacket(proto, src, dst, sport, dport, ttl);
        Console.WriteLine($"[inject] ifIdx={ifIdx} subIfIdx={subIfIdx} {protoName} {Format(src)} -> {Format(dst)}" +
                          (proto == 1 ? $" id={sport}" : $" {sport}->{dport}") + $" ttl={ttl} len={packet.Length} count={count}");

        for (var i = 0; i < count; i++)
        {
            if (TryInject(sender, packet, ifIdx, subIfIdx!.Value, out var win32)) injected++;
            else Console.WriteLine($"[inject] packet {i + 1}: WinDivertSend failed, error {win32}");
            if (i + 1 < count) Thread.Sleep(intervalMs);
        }
        Console.WriteLine($"[inject] injected {injected} of {count}");
    }
    else
    {
        Console.WriteLine(showAny
            ? $"[inject] observing every packet on ifIdx {ifIdx} (filter '{filter}'), injecting nothing"
            : $"[inject] observing {protoName} between {Format(src)} and {Format(dst)} only, injecting nothing");
    }

    Thread.Sleep(watchSec * 1000);
    state.Stop = true;
    pre.Shutdown(ShutdownMode.Recv);
    post.Shutdown(ShutdownMode.Recv);
    if (fwd is { } forwardHandle)
    {
        transit.Stop = true;
        forwardHandle.Shutdown(ShutdownMode.Recv);
    }
    if (fwdBelow is { } belowHandle)
    {
        transitBelow.Stop = true;
        belowHandle.Shutdown(ShutdownMode.Recv);
    }

    if (showFwd)
    {
        ReportForward(transit, "above Router", src, dst);
        ReportForward(transitBelow, "below Router", src, dst);
    }

    Console.WriteLine($"[inject] the network-layer readers delivered {state.PreTotal} packets above this program's " +
                      $"injection and {state.PostTotal} below it; Router works on the forward layer and is reported " +
                      $"separately, because a priority orders the handles of one layer only; " +
                      $"{state.Unrelated} of those carried neither address and were not printed");
    if (showAny)
    {
        Console.WriteLine($"[inject] on ifIdx {ifIdx}: {state.InboundLan} arrived from the client, " +
                          $"{state.OutboundLan} left this host towards it; both printed whatever they carry");
        if (dst != 0)
        {
            Console.WriteLine($"[inject] everything {Format(src)} sent above Router, by destination - {state.ToDst} of them to {Format(dst)}:");
            Console.WriteLine($"[inject] (the count above is IPv4's alone: {state.NotIpv4} packets above Router carried " +
                              "another version and entered no tally)");
        }
        else
            Console.WriteLine($"[inject] no --dst, so nothing is tallied against a pair: {state.NotIpv4} packets of " +
                              "another version were seen above, and IPv6 ones were printed in the form above");
        lock (state.FromSrcGate)
        {
            foreach (var (where, hits) in state.FromSrc.OrderByDescending(static e => e.Value).Take(10))
                Console.WriteLine($"[inject]   {hits,5}  -> {where}");
            foreach (var (where, hits) in state.ToSrc.OrderByDescending(static e => e.Value).Take(10))
                Console.WriteLine($"[inject]   {hits,5}  <- {where}");
        }
    }
    Console.WriteLine($"[inject] of this exchange, at the network layer: {state.PreForward} seen above the injection, " +
                      $"{state.PostForward} below it unchanged, {state.PostRewritten} below it with the source " +
                      $"rewritten, {state.PostReverse} answering it");
    if (state.V6Seen > 0)
        Console.WriteLine($"[inject] {state.V6Seen} IPv6 packets reached the pre reader" +
                          (showAny ? $" (the first {PrintCap} printed above)" : " (pass --any to print them)") +
                          "; no count on this page includes them.");
    Console.WriteLine(state switch
    {
        _ when state.PreTotal == 0 && state.PostTotal == 0
            => "[inject] neither network-layer reader saw a single packet, so this program observed nothing at all " +
               "and says nothing about the client.",
        _ when showAny && state.InboundLan == 0
            => $"[inject] the readers were alive and carried other traffic, but nothing at all arrived " +
               $"inbound on ifIdx {ifIdx}: the client's frames are not being delivered to this host at all.",
        _ when showAny && dst != 0 && state.ToDst == 0
            => $"[inject] the client's packets arrived and were tallied, and none of them was addressed to " +
               $"{Format(dst)}: what is missing is the client sending it, not this host forwarding it. The " +
               "destination list above is the answer.",
        _ => "[inject] the network layer answers only whether the client's packets reach this host; a packet this " +
               "host routes is not reported here at all, which is the whole difference between the two layers.",
    });
    if (showFwd)
        Console.WriteLine((transit, transitBelow) switch
        {
            _ when transit.PostForward + transit.ForeignToDst == 0
                => "[inject] the forwarding path carried nothing of this exchange: the packet never got as far as " +
                   "the routing decision, so it was lost above Router rather than by it.",
            _ when transitBelow.ImpostorTotal + transitBelow.PostForward + transitBelow.ForeignToDst == 0
                => "[inject] the request reached the forwarding path and nothing came back below Router's priority: " +
                   "Router took it and put nothing back. Its own counters name the branch, and a reinjection that " +
                   "failed shows there as passthroughfail/rewritefail.",
            _ when transitBelow.ForeignToDst > 0
                => "[inject] below Router the packet heading for the destination carries a source that is not the " +
                   "client's: the NAT rewrote it, and the copy is back on the forwarding path.",
            _ when transitBelow.PostForward > 0
                => "[inject] below Router the client's own address is still in it, and there are two readings of " +
                   "that: Router's recv= counter separates them. recv=0 means the packet never entered the handle " +
                   "- the filter asks for not impostor, and this program's own injection is flagged impostor by " +
                   "the time it reaches the forwarding path - while recv>0 with snat=0 means a handle took it and " +
                   "one of the branches that return no action did.",
            _ => "[inject] something came back below Router but not this exchange, so the shape list above is the " +
                  "reading and this line is not.",
        });
    else
        Console.WriteLine("[inject] no --fwd reader, so nothing here says what Router did: its capture point is the " +
                          "forwarding path and this run watched only this host's own traffic.");
    return injected == count ? 0 : 1;
}

// A struct this size fits, and the header's own definition puts the transport header straight after
// it. The fields are written in wire order; BinaryPrimitives is the only place byte order appears.
static byte[] BuildPacket(byte proto, uint src, uint dst, ushort a, ushort b, byte ttl)
{
    var transport = proto switch { 1 => 16, 17 => 16, _ => 20 };
    var packet = new byte[20 + transport];

    packet[0] = 0x45;
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), (ushort)packet.Length);
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4, 2), 0x1122);
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(6, 2), 0x4000);
    packet[8] = ttl;
    packet[9] = proto;
    BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(12, 4), src);
    BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(16, 4), dst);

    switch (proto)
    {
        case 1:
            packet[20] = 8;
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(24, 2), a);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(26, 2), 1);
            for (var i = 0; i < 8; i++) packet[28 + i] = (byte)(0xA0 + i);
            break;
        case 17:
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(20, 2), a);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(22, 2), b);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(24, 2), 16);
            for (var i = 0; i < 8; i++) packet[28 + i] = (byte)(0xA0 + i);
            break;
        default:
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(20, 2), a);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(22, 2), b);
            BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(24, 4), 0x99001122);
            // RFC 9293 §3.1: the header's own length is the octet before the flags, in 32-bit words, so
            // 20 octets of header is 5 in the high nibble; the flags octet is next, then the window.
            packet[32] = 0x50;
            packet[33] = 0x02;
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(34, 2), 64240);
            break;
    }
    return packet;
}

static unsafe bool TryInject(WinDivertHandle handle, byte[] packet, int ifIdx, int subIfIdx, out int win32)
{
    var buffer = Marshal.AllocHGlobal(packet.Length);
    var address = Marshal.AllocHGlobal(ADDR_SIZE);
    try
    {
        Marshal.Copy(packet, 0, buffer, packet.Length);
        var addr = (Address*)address;
        addr->Flags = AddressFlag.None;
        addr->IfIdx = ifIdx;
        addr->SubIfIdx = subIfIdx;
        // An injected packet must carry correct checksums or have the matching *Checksum flag clear;
        // calculating them here is what makes leaving those flags off a statement rather than an accident.
        handle.CalcChecksums((void*)buffer, packet.Length, addr);
        if (handle.Send((void*)buffer, packet.Length, null, addr))
        {
            win32 = 0;
            return true;
        }
        win32 = Marshal.GetLastWin32Error();
        return false;
    }
    finally
    {
        Marshal.FreeHGlobal(buffer);
        Marshal.FreeHGlobal(address);
    }
}

static unsafe void ReadLoop(WinDivertHandle handle, string tag, int ifIdx, uint src, uint dst,
    State state, bool calibrate, bool showAny)
{
    var buffer = Marshal.AllocHGlobal(MTU_MAX);
    var address = Marshal.AllocHGlobal(ADDR_SIZE);
    try
    {
        while (!state.Stop)
        {
            int length;
            if (!handle.Recv((void*)buffer, MTU_MAX, &length, (Address*)address))
            {
                if (state.Stop) return;
                Console.WriteLine($"[inject] {tag} WinDivertRecv failed: {Marshal.GetLastWin32Error()}");
                state.Stop = true;
                return;
            }
            var packet = new ReadOnlySpan<byte>((void*)buffer, length);
            var addr = (Address*)address;
            var outbound = (addr->Flags & AddressFlag.Outbound) != 0;
            var impostor = (addr->Flags & AddressFlag.Impostor) != 0;

            // Counted before any filter of this program's, so that "nothing printed" can be told apart
            // from "nothing arrived": a reader that is alive but seeing no traffic and a dead handle look
            // identical in the printed lines.
            if (calibrate) Interlocked.Increment(ref state.PreTotal);
            else Interlocked.Increment(ref state.PostTotal);

            // Only the pre-Router view can vouch for a sub-interface index: below Router every packet
            // has been reinjected, and carries whatever the one that reinjected it chose to say.
            if (calibrate && !outbound && !impostor && addr->IfIdx == ifIdx && state.SubIfIdx is null)
                state.SubIfIdx = addr->SubIfIdx;

            // Counted before the version test, because "the client sent nothing off-link" is only worth
            // anything if a client that sent it over IPv6 would have shown up as not-IPv4 rather than as a
            // zero. The pair accounting below reads an IPv4 header only; IPv6 is read for the line in the
            // next branch and goes no further.
            if (calibrate && packet.Length >= 1 && (packet[0] >> 4) != 4)
                Interlocked.Increment(ref state.NotIpv4);

            // Only the pre reader, and deliberately without the onLan test that gates the IPv4 lines: an
            // ICMPv6 packet is here because the filter asked for it, and hiding one whose interface index
            // was a surprise is exactly how a probe turns into a false null. The index is printed instead.
            if (calibrate && packet.Length >= 40 && (packet[0] >> 4) == 6)
            {
                var v6 = Interlocked.Increment(ref state.V6Seen);
                if (showAny && v6 <= PrintCap)
                    Console.WriteLine($"[watch] {tag} ifIdx={addr->IfIdx,-4} sub={addr->SubIfIdx,-4} dir={(outbound ? "out" : "in"),-3} " +
                                      $"impostor={impostor,-5} len={length,-5} {DescribeV6(packet)}");
            }

            if (packet.Length < 20 || (packet[0] >> 4) != 4) continue;
            var a = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(12, 4));
            var b = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(16, 4));

            // Where the client is actually talking, tallied over every packet instead of left to whichever
            // lines happened to still be on screen. The pre view only, so a packet counts once.
            if (calibrate)
            {
                var head = (packet[0] & 0x0F) * 4;
                var far = (ushort)(packet.Length >= head + 4 ? BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(head + 2, 2)) : 0);
                var near = (ushort)(packet.Length >= head + 2 ? BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(head, 2)) : 0);
                if (b == dst) Interlocked.Increment(ref state.ToDst);
                lock (state.FromSrcGate)
                {
                    if (a == src)
                        Tally(state.FromSrc, packet[9], Format(b), far);
                    else if (b == src)
                        Tally(state.ToSrc, packet[9], Format(a), near);
                }
            }

            // The three legs of the injected exchange, and nothing else. A leased phone puts several DNS
            // queries a second through this interface, and on a console that shows sixteen lines that
            // buries the lines the run is about - so the rest is counted, not printed.
            var isPair = a == src && b == dst;
            var isAnswer = a == dst && b == src;
            var isRewritten = !isPair && !isAnswer && b == dst;

            // --any asks the arrival question, which the pair filter cannot: a client whose packet never
            // reaches this layer and a client whose packet carries some other address both print nothing.
            // Both directions on the LAN interface are printed, because whether this host answers a client
            // is the same question asked from the other side.
            var onLan = showAny && addr->IfIdx == ifIdx;
            if (onLan)
            {
                if (outbound) Interlocked.Increment(ref state.OutboundLan);
                else Interlocked.Increment(ref state.InboundLan);
            }
            if (!isPair && !isAnswer && !isRewritten && !onLan)
            {
                Interlocked.Increment(ref state.Unrelated);
                continue;
            }
            if (isPair && calibrate) Interlocked.Increment(ref state.PreForward);
            if (isPair && !calibrate) Interlocked.Increment(ref state.PostForward);
            if (isRewritten && !calibrate) Interlocked.Increment(ref state.PostRewritten);
            if (isAnswer && !calibrate) Interlocked.Increment(ref state.PostReverse);

            Interlocked.Increment(ref state.Seen);
            var ihl = (packet[0] & 0x0F) * 4;
            Console.WriteLine($"[watch] {tag} ifIdx={addr->IfIdx,-4} sub={addr->SubIfIdx,-4} dir={(outbound ? "out" : "in"),-3} " +
                              $"impostor={impostor,-5} ttl={packet[8],-3} frag={((packet[6] & 0x20) != 0),-5} " +
                              $"len={length,-5} {Describe(packet, ihl)}");
        }
    }
    finally
    {
        Marshal.FreeHGlobal(buffer);
        Marshal.FreeHGlobal(address);
    }
}

// One forward reader's reading, printed the same way for both halves of the comparison.
static void ReportForward(State into, string where, uint src, uint dst)
{
    Console.WriteLine($"[inject] Layer.Forward {where}: {into.ForwardTotal} packets delivered to the handle");
    lock (into.FromSrcGate)
    {
        foreach (var (shape, hits) in into.Shapes.OrderByDescending(static e => e.Value).Take(6))
            Console.WriteLine($"[inject]   {hits,5}  shape {shape}");
        foreach (var (destination, hits) in into.FromSrc.OrderByDescending(static e => e.Value).Take(10))
            Console.WriteLine($"[inject]   {hits,5}  -> {destination}");
    }
    Console.WriteLine($"[inject]   of those, {into.ToDst} carried {Format(dst)} as destination, {into.PostForward} the " +
                      $"{Format(src)} -> {Format(dst)} request, {into.PostReverse} its answer, {into.ForeignToDst} " +
                      $"headed for {Format(dst)} from an address that is not the client's, which is what a source " +
                      "rewrite looks like; either count alone is this host's own traffic");
    // Named separately because the flag does not mean what it looks like here: upstream defines an impostor
    // as any packet injected by a driver, which includes this program's own, so the count says nothing about
    // whether Router put anything back on the path.
    Console.WriteLine($"[inject]   {into.ImpostorTotal} carried the impostor flag, which this program's own " +
                      "injection sets before Router is ever asked - it is provenance, not a reinjection.");
}

// A reader on Layer.Forward, which upstream documents as "Network packets passing through the local
// machine", where Layer.Network is "Network packets to/from the local machine". A router only ever deals
// in the first kind, and the Network.* address fields are valid at both layers.
//
// The address shape is the measurement here, not the packet contents: whether a transit packet is tagged
// with the interface it arrived on or the one it leaves by, and which direction bit it carries, is what
// decides how a rewrite has to be reinjected. A shape is printed the first time and counted after that,
// because a client burst of 600 packets would otherwise bury the one line that says what the shape is.
static unsafe void TransitLoop(WinDivertHandle handle, uint src, uint dst, State state, string label)
{
    var buffer = Marshal.AllocHGlobal(MTU_MAX);
    var address = Marshal.AllocHGlobal(ADDR_SIZE);
    try
    {
        while (!state.Stop)
        {
            int length;
            if (!handle.Recv((void*)buffer, MTU_MAX, &length, (Address*)address))
            {
                if (state.Stop) return;
                Console.WriteLine($"[inject] fwd {label} WinDivertRecv failed: {Marshal.GetLastWin32Error()}");
                state.Stop = true;
                return;
            }
            var packet = new ReadOnlySpan<byte>((void*)buffer, length);
            var addr = (Address*)address;
            Interlocked.Increment(ref state.ForwardTotal);
            if (packet.Length < 20 || (packet[0] >> 4) != 4) continue;
            var a = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(12, 4));
            var b = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(16, 4));
            var ihl = (packet[0] & 0x0F) * 4;
            var far = (ushort)(packet.Length >= ihl + 4 ? BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ihl + 2, 2)) : (ushort)0);
            var near = (ushort)(packet.Length >= ihl + 2 ? BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ihl, 2)) : (ushort)0);

            var outbound = (addr->Flags & AddressFlag.Outbound) != 0;
            var impostor = (addr->Flags & AddressFlag.Impostor) != 0;
            var loopback = (addr->Flags & AddressFlag.Loopback) != 0;
            var shape = $"ifIdx={addr->IfIdx} sub={addr->SubIfIdx} dir={(outbound ? "out" : "in")} " +
                        $"impostor={impostor} loopback={loopback}";
            bool firstShape;
            lock (state.FromSrcGate)
            {
                firstShape = !state.Shapes.ContainsKey(shape);
                state.Shapes[shape] = state.Shapes.TryGetValue(shape, out var hits) ? hits + 1 : 1;
                if (a == src) Tally(state.FromSrc, packet[9], Format(b), far);
                else if (b == src) Tally(state.ToSrc, packet[9], Format(a), near);
            }
            if (b == dst) Interlocked.Increment(ref state.ToDst);
            if (a == src && b == dst) Interlocked.Increment(ref state.PostForward);
            if (a == dst && b == src) Interlocked.Increment(ref state.PostReverse);
            // Two readings that only make sense together: the flag says a handle put this copy back on the
            // path, and a copy heading for the destination from an address that is not the client's is what
            // a source rewrite looks like. Either alone is the host's own traffic.
            if (impostor) Interlocked.Increment(ref state.ImpostorTotal);
            if (b == dst && a != src && a != dst) Interlocked.Increment(ref state.ForeignToDst);

            var printed = Interlocked.Increment(ref state.Seen);
            if (!firstShape && printed > PrintCap) continue;
            Console.WriteLine($"[watch] fwd {label,-6} {shape,-64} ttl={packet[8],-3} len={length,-5} {Describe(packet, ihl)}" +
                              (firstShape ? "   <== first packet of this shape" : ""));
        }
    }
    finally
    {
        Marshal.FreeHGlobal(buffer);
        Marshal.FreeHGlobal(address);
    }
}

// One line of the tally. The port is the one the peer speaks from or to, which is what tells a client's
// query apart from this host's answer to it.
static void Tally(Dictionary<string, int> into, byte proto, string address, ushort port)
{
    var key = proto switch
    {
        1 => $"icmp {address}",
        6 => $"tcp {address}:{port}",
        17 => $"udp {address}:{port}",
        _ => $"proto{proto} {address}"
    };
    into[key] = into.TryGetValue(key, out var hits) ? hits + 1 : 1;
}

static string Describe(ReadOnlySpan<byte> packet, int ihl)
{
    var proto = packet[9];
    var src = Format(BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(12, 4)));
    var dst = Format(BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(16, 4)));
    if (proto == 1 && packet.Length >= ihl + 6)
        return $"icmp type={packet[ihl]} id={BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ihl + 4, 2))} {src} -> {dst}";
    if (proto is 6 or 17 && packet.Length >= ihl + 4)
    {
        var sport = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ihl, 2));
        var dport = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ihl + 2, 2));
        var suffix = proto == 6 && packet.Length >= ihl + 14 ? $" flags=0x{packet[ihl + 13]:X2}" : "";
        return $"{(proto == 6 ? "tcp" : "udp")} {src}:{sport} -> {dst}:{dport}{suffix}";
    }
    return $"proto{proto} {src} -> {dst}";
}

// One line for an IPv6 packet: the types are the neighbour-exchange ones plus the errors a router sends,
// anything else prints its number. NS and NA carry the address being asked about at a fixed offset, and an
// NA's flags byte is what distinguishes "I am the target" from "I am a router" - the two fields a responder
// has to get right.
static string DescribeV6(ReadOnlySpan<byte> packet)
{
    var next = packet[6];
    var src = new IPAddress(packet[8..24]);
    var dst = new IPAddress(packet[24..40]);
    if (next != 58 || packet.Length < 42) return $"next={next} len={packet.Length} {src} -> {dst}";
    var type = packet[40];
    var name = type switch
    {
        1 => "destination-unreachable",
        2 => "packet-too-big",
        3 => "time-exceeded",
        128 => "echo-request",
        129 => "echo-reply",
        133 => "router-solicitation",
        134 => "router-advertisement",
        135 => "neighbor-solicitation",
        136 => "neighbor-advertisement",
        _ => "other"
    };
    var target = type is 135 or 136 && packet.Length >= 64 ? $" target={new IPAddress(packet[48..64])}" : "";
    var flags = type == 136 ? $" flags=0x{packet[41]:X2}" : "";
    return $"icmpv6 type={type} ({name}) {src} -> {dst}{target}{flags}";
}

static uint ParseAddress(string name, string text)
{
    var parts = text.Split('.');
    if (parts.Length != 4) throw new FormatException($"{name} {text}: not four dotted octets");
    uint address = 0;
    foreach (var part in parts)
    {
        if (!byte.TryParse(part, out var octet)) throw new FormatException($"{name} {text}: {part} is not an octet");
        address = address << 8 | octet;
    }
    return address;
}

static int Number(string name, string text)
{
    if (!int.TryParse(text, out var value)) throw new FormatException($"{name} {text}: not a number");
    return value;
}

// The four octets read big-endian, so 192.168.122.100 is 0xC0A87A64 here and on the wire.
static string Format(uint address)
    => $"{address >> 24 & 0xFF}.{address >> 16 & 0xFF}.{address >> 8 & 0xFF}.{address & 0xFF}";

sealed class State
{
    public int Seen;
    public int PreTotal;
    public int PostTotal;
    public int PreForward;
    public int PostForward;
    public int PostRewritten;
    public int PostReverse;
    public int Unrelated;
    public int InboundLan;
    public int OutboundLan;
    public int NotIpv4;
    public int V6Seen;
    public int ToDst;
    public int ForwardTotal;
    public int ImpostorTotal;
    public int ForeignToDst;
    public readonly Dictionary<string, int> Shapes = new();
    public readonly Dictionary<string, int> FromSrc = new();
    public readonly Dictionary<string, int> ToSrc = new();
    public readonly object FromSrcGate = new();
    public int? SubIfIdx;
    public volatile bool Stop;
}
