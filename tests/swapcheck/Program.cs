using System.Buffers.Binary;
using System.Net;
using TlsMitm;
using static TlsMitm.WinDivertPInvoke;

// Offline judgement for the redirector's packet rewrite: no driver, no admin, no socket. The address and
// port writes are separated from the WinDivert send (PacketRewrite), so a crafted packet can be pinned,
// rewritten, and read back byte for byte. This is the leg the rest of the offline suite never touches -
// FakeRedirector hands the proxy a destination directly and no packet is ever swapped.
// Assertions read the raw wire bytes, not the struct fields, so they do not share the product's byte-order
// convention: an address is compared to IPAddress.GetAddressBytes(), a port is read big-endian.
var failures = new List<string>();
var notes = new List<string>();

var client = IPAddress.Parse("192.0.2.10");
var server = IPAddress.Parse("198.51.100.7");
var local = IPAddress.Parse("192.0.2.1");
var lan6 = IPAddress.Parse("2001:db8::1");
var client6 = IPAddress.Parse("2001:db8::10");
var server6 = IPAddress.Parse("2001:db8::99");
const ushort ClientPort = 50000, ServerPort = 443, Token = 49152, RelayPort = 8443;

static uint A4(IPAddress a) => BitConverter.ToUInt32(a.GetAddressBytes());
static (ulong Hi, ulong Lo) A6(IPAddress a)
{
    var b = a.GetAddressBytes();
    return (BitConverter.ToUInt64(b, 0), BitConverter.ToUInt64(b, 8));
}

byte[] V4Packet(IPAddress src, IPAddress dst, ushort sport, ushort dport)
{
    var p = new byte[40];
    p[0] = 0x45;                       // version 4, IHL 5
    p[8] = 64;                         // TTL
    p[9] = 6;                          // protocol TCP
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), 40);
    src.GetAddressBytes().CopyTo(p, 12);
    dst.GetAddressBytes().CopyTo(p, 16);
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(20), sport);
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(22), dport);
    BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(24), 0x11223344);   // seq
    BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(28), 0x55667788);   // ack
    p[32] = 0x50;                      // data offset 5
    return p;
}

byte[] V6Packet(IPAddress src, IPAddress dst, ushort sport, ushort dport)
{
    var p = new byte[60];
    p[0] = 0x60;                       // version 6
    p[6] = 6;                          // next header TCP
    p[7] = 64;                         // hop limit
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(4), 20);            // payload length
    src.GetAddressBytes().CopyTo(p, 8);
    dst.GetAddressBytes().CopyTo(p, 24);
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(40), sport);
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(42), dport);
    p[52] = 0x50;
    return p;
}

void Expect(bool ok, string what)
{
    if (!ok) failures.Add(what);
    Console.WriteLine($"{(ok ? "ok  " : "FAIL")} {what}");
}

bool Addr4(byte[] p, int off, IPAddress a) => p.AsSpan(off, 4).SequenceEqual(a.GetAddressBytes());
bool Addr6(byte[] p, int off, IPAddress a) => p.AsSpan(off, 16).SequenceEqual(a.GetAddressBytes());
ushort Port(byte[] p, int off) => BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(off));

// --- forward v4: the client's packet becomes the server's packet to this host's relay ----------------
unsafe
{
    var p = V4Packet(client, server, ClientPort, ServerPort);
    fixed (byte* ptr = p)
    {
        PacketRewrite.ForwardV4((NativeIpv4Header*)ptr, (NativeTcpHeader*)(ptr + 20),
            A4(server), A4(local), Token, RelayPort, loopback: false);
    }
    Expect(Addr4(p, 12, server), "forward v4 puts the original server in the source");
    Expect(Addr4(p, 16, local), "forward v4 delivers to this host's local endpoint");
    Expect(Port(p, 20) == Token, $"forward v4 replaces the source port with the token, got {Port(p, 20)}");
    Expect(Port(p, 22) == RelayPort, $"forward v4 aims the destination at the relay port, got {Port(p, 22)}");
    Expect(p[8] == 64 && p[9] == 6, "forward v4 leaves TTL and protocol alone");
    Expect(BinaryPrimitives.ReadUInt32BigEndian(p.AsSpan(24)) == 0x11223344, "forward v4 leaves the sequence number alone");

    // A retransmitted packet is rewritten again from the same flow: the result must not drift.
    var before = p.ToArray();
    fixed (byte* ptr = p)
    {
        PacketRewrite.ForwardV4((NativeIpv4Header*)ptr, (NativeTcpHeader*)(ptr + 20),
            A4(server), A4(local), Token, RelayPort, loopback: false);
    }
    Expect(p.SequenceEqual(before), "a retransmitted forward v4 packet rewrites to the same bytes");
}

// --- forward v4 loopback: ports still move, addresses stay -------------------------------------------
unsafe
{
    var lo = IPAddress.Parse("127.0.0.1");
    var p = V4Packet(lo, lo, ClientPort, ServerPort);
    fixed (byte* ptr = p)
    {
        PacketRewrite.ForwardV4((NativeIpv4Header*)ptr, (NativeTcpHeader*)(ptr + 20),
            A4(lo), A4(lo), Token, RelayPort, loopback: true);
    }
    Expect(Addr4(p, 12, lo) && Addr4(p, 16, lo), "forward v4 loopback leaves both addresses alone");
    Expect(Port(p, 20) == Token && Port(p, 22) == RelayPort, "forward v4 loopback still swaps the ports");
}

// --- reverse v4: the relay's answer becomes the server's answer to the client ------------------------
unsafe
{
    var p = V4Packet(server, local, RelayPort, Token);
    fixed (byte* ptr = p)
    {
        PacketRewrite.ReverseV4((NativeIpv4Header*)ptr, (NativeTcpHeader*)(ptr + 20),
            A4(server), A4(client), ServerPort, ClientPort, loopback: false);
    }
    Expect(Addr4(p, 12, server), "reverse v4 restores the original server as the source");
    Expect(Addr4(p, 16, client), "reverse v4 aims the answer at the client's own address");
    Expect(Port(p, 20) == ServerPort, $"reverse v4 restores the server port, got {Port(p, 20)}");
    Expect(Port(p, 22) == ClientPort, $"reverse v4 restores the client port, got {Port(p, 22)}");
}

// --- forward v6, local delivery: destination is the client's own address -----------------------------
unsafe
{
    var p = V6Packet(client6, server6, ClientPort, ServerPort);
    var (sh, sl) = A6(server6);
    var (dh, dl) = A6(client6);
    fixed (byte* ptr = p)
    {
        PacketRewrite.ForwardV6((NativeIpv6Header*)ptr, (NativeTcpHeader*)(ptr + 40),
            sh, sl, dh, dl, Token, RelayPort, loopback: false);
    }
    Expect(Addr6(p, 8, server6), "forward v6 puts the original server in the source");
    Expect(Addr6(p, 24, client6), "forward v6 local delivery aims at the client's own address");
    Expect(Port(p, 40) == Token && Port(p, 42) == RelayPort, "forward v6 swaps the ports");
    Expect(p[7] == 64 && p[6] == 6, "forward v6 leaves hop limit and next header alone");
}

// --- forward v6, forwarded delivery: destination is the LAN address ----------------------------------
unsafe
{
    var p = V6Packet(client6, server6, ClientPort, ServerPort);
    var (sh, sl) = A6(server6);
    var (lh, ll) = A6(lan6);
    fixed (byte* ptr = p)
    {
        PacketRewrite.ForwardV6((NativeIpv6Header*)ptr, (NativeTcpHeader*)(ptr + 40),
            sh, sl, lh, ll, Token, RelayPort, loopback: false);
    }
    Expect(Addr6(p, 8, server6), "forward v6 forwarded keeps the server as the source");
    Expect(Addr6(p, 24, lan6), "forward v6 forwarded delivers to the LAN address, not the client's");
}

// --- reverse v6: addresses come from the flow key ----------------------------------------------------
unsafe
{
    var p = V6Packet(server6, lan6, RelayPort, Token);
    var (sh, sl) = A6(server6);
    var (ch, cl) = A6(client6);
    fixed (byte* ptr = p)
    {
        PacketRewrite.ReverseV6((NativeIpv6Header*)ptr, (NativeTcpHeader*)(ptr + 40),
            sh, sl, ch, cl, ServerPort, ClientPort, loopback: false);
    }
    Expect(Addr6(p, 8, server6), "reverse v6 restores the server as the source");
    Expect(Addr6(p, 24, client6), "reverse v6 aims the answer at the client");
    Expect(Port(p, 40) == ServerPort && Port(p, 42) == ClientPort, "reverse v6 restores both ports");

    var before = p.ToArray();
    fixed (byte* ptr = p)
    {
        PacketRewrite.ReverseV6((NativeIpv6Header*)ptr, (NativeTcpHeader*)(ptr + 40),
            sh, sl, ch, cl, ServerPort, ClientPort, loopback: false);
    }
    Expect(p.SequenceEqual(before), "a retransmitted reverse v6 packet rewrites to the same bytes");
}

foreach (var note in notes) Console.WriteLine($"[swapcheck] note: {note}");
if (failures.Count > 0)
{
    Console.WriteLine($"[swapcheck] FAIL ({failures.Count})");
    return 1;
}
Console.WriteLine("[swapcheck] PASS - forward/reverse rewrite, both families, loopback, forwarded delivery, retransmission idempotence");
return 0;
