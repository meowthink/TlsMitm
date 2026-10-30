using System.Buffers.Binary;
using TlsMitm;

// Offline judgement for the QUIC signature the blocker drops on: no driver, no sockets. Each case
// builds the datagram the RFC describes and asserts what QuicSignature makes of it, so a version read
// from the wrong offset cannot pass unnoticed.

var failures = new List<string>();

void Expect(bool condition, string what)
{
    Console.WriteLine((condition ? "ok   " : "FAIL ") + what);
    if (!condition) failures.Add(what);
}

bool Judge(byte[] packet, out ushort dstPort)
{
    unsafe
    {
        fixed (byte* p = packet) return QuicSignature.IsQuicDatagram(p, packet.Length, out dstPort);
    }
}

// RFC 9000 §17.2: Long Header, Fixed Bit, type Initial, packet-number length 3 -> 0xc3, then Version.
// The remaining bytes only have to be long enough for the version test.
var v1 = new byte[] { 0xC3, 0x00, 0x00, 0x00, 0x01, 0x08, 0, 1, 2, 3, 4, 5, 6, 7, 0x00, 0x00, 0x44, 0x9E };
var v2 = new byte[] { 0xC3, 0x6B, 0x33, 0x43, 0xCF, 0x08, 0, 1, 2, 3, 4, 5, 6, 7, 0x00, 0x00, 0x44, 0x9E };
// Type Handshake (0b10) with the same fixed bits: still a long header, so still QUIC.
var handshake = new byte[] { 0xE3, 0x00, 0x00, 0x00, 0x01, 0x08, 0, 1, 2, 3, 4, 5, 6, 7 };
// The same first byte with a version that belongs to no QUIC specification.
var notQuicVersion = new byte[] { 0xC3, 0x00, 0x00, 0x00, 0x02, 0x08, 0, 1, 2 };
// A DTLS record: handshake content type, epoch 0, sequence number, version ff fe fd.
var dtls = new byte[] { 0x16, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
// A QUIC 1-RTT short header (Header Form = 0): deliberately not recognised, see QuicSignature.
var shortHeader = new byte[] { 0x43, 0x08, 0, 1, 2, 3, 4, 5, 6, 7 };

var ok = Judge(V4(17, 50000, 443, v1, ihl: 5), out var port);
Expect(ok && port == 443, $"a QUIC v1 Initial to UDP/443 is QUIC (port {port})");

ok = Judge(V4(17, 50000, 9999, v1, ihl: 5), out port);
Expect(ok && port == 9999, $"a QUIC v1 Initial on an unrelated port is QUIC too (port {port})");

Expect(Judge(V4(17, 50000, 443, v2, ihl: 5), out _), "a QUIC v2 Initial is QUIC");

Expect(Judge(V4(17, 50000, 443, handshake, ihl: 5), out _), "a QUIC long header of type Handshake is QUIC");

Expect(!Judge(V4(17, 50000, 443, notQuicVersion, ihl: 5), out _),
    "the same first byte with an unrelated version is not QUIC");

Expect(!Judge(V4(17, 50000, 443, dtls, ihl: 5), out _), "a DTLS record is not QUIC");

Expect(!Judge(V4(17, 50000, 443, shortHeader, ihl: 5), out _),
    "a QUIC short header is not matched (it carries no version)");

Expect(!Judge(V4(6, 50000, 443, v1, ihl: 5), out _), "a TCP packet carrying a QUIC-looking payload is not QUIC");

ok = Judge(V4(17, 50000, 443, v1, ihl: 6), out port);
Expect(ok && port == 443, "IPv4 options do not shift the UDP header out of place");

ok = Judge(V6(17, 443, v1), out port);
Expect(ok && port == 443, $"an IPv6 UDP datagram carrying a QUIC v1 Initial is QUIC (port {port})");

// RFC 9000 §17.2 puts the version immediately after the flags byte, so the same four bytes one place
// later describe no QUIC version at all. Reading from the wrong offset would judge both.
var versionShifted = new byte[] { 0xC3, 0x00, 0x00, 0x01, 0x00, 0x08, 0, 1, 2, 3 };
Expect(!Judge(V4(17, 50000, 443, versionShifted, ihl: 5), out _),
    "version 1 read from bytes 2-5 instead of 1-4 is not accepted");

// A Version Negotiation packet carries version 0 with a non-empty Destination Connection ID (RFC 9000
// §17.2.1). It is left relayed: the blocker stops the handshakes that would otherwise complete over
// QUIC, and a datagram this host has no way to answer is not one of them.
var versionNegotiation = new byte[] { 0xC3, 0x00, 0x00, 0x00, 0x00, 0x08, 0, 1, 2, 3, 4, 5, 6, 7 };
Expect(!Judge(V4(17, 50000, 443, versionNegotiation, ihl: 5), out _),
    "a version negotiation packet (version 0) is relayed, not dropped");

// Header Form set with the Fixed Bit cleared: RFC 9000 §17.2 makes a receiver discard it, so it is not
// a session worth dropping either - and the two bits are checked together, which this pins.
Expect(!Judge(V4(17, 50000, 443, new byte[] { 0x83, 0x00, 0x00, 0x00, 0x01, 0x08, 0, 1, 2, 3 }, ihl: 5), out _),
    "a long header with the fixed bit cleared is not QUIC");

// RFC 8200 §4: the next header is the byte that says what follows the fixed header. An extension header
// in front of the UDP header is not followed, so this datagram is left alone rather than judged from
// the wrong offset.
Expect(!Judge(V6(43, 443, v1), out _), "an IPv6 datagram with a routing header before UDP is not judged");

// --- what a short buffer must never do: read past it ---------------------------------------------

// IPv4 IHL is in 4-byte words (RFC 791 §3.1), so 15 claims a 60-byte header. A packet that short
// cannot hold a UDP header, and the length guard is what keeps the parser off the bytes after it.
var overrun = V4(17, 50000, 443, v1, ihl: 15);
Expect(!Judge(overrun[..30], out _), "an IPv4 header length past the end of the packet is not read");

// The 8-byte UDP header itself (RFC 768) has to be whole before its port fields are used.
Expect(!Judge(V4(17, 50000, 443, v1, ihl: 5)[..(20 + 4)], out _),
    "a packet cut inside the UDP header is not QUIC");
Expect(!Judge(V6(17, 443, v1)[..(40 + 7)], out _),
    "an IPv6 packet cut inside the UDP header is not QUIC");
Expect(!Judge(V6(17, 443, v1)[..20], out _),
    "an IPv6 packet shorter than its fixed header is not read");

Expect(!Judge(V4(17, 50000, 443, v1[..4], ihl: 5), out _), "a payload shorter than the version field is not QUIC");

// The same boundary from the other side: flags plus the four version bytes is the shortest datagram
// that can be judged, and nothing shorter is needed to call it.
Expect(Judge(V4(17, 50000, 443, new byte[] { 0xC3, 0x00, 0x00, 0x00, 0x01 }, ihl: 5), out _),
    "five payload bytes are enough to recognise QUIC");

if (failures.Count > 0)
{
    Console.WriteLine($"\nquiccheck FAIL ({failures.Count})");
    return 1;
}
Console.WriteLine("\nquiccheck PASS - 20 cases");
return 0;

// --- datagram builders --------------------------------------------------------------------------
static byte[] V4(byte protocol, ushort sport, ushort dport, byte[] payload, int ihl)
{
    var headerLen = ihl * 4;
    var packet = new byte[headerLen + 8 + payload.Length];
    packet[0] = (byte)(0x40 | ihl);
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), (ushort)packet.Length);
    packet[8] = 64;
    packet[9] = protocol;
    BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(12, 4), 0xC0A80032); // 192.168.0.50
    BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(16, 4), 0x0E000203); // 14.0.2.3
    Udp(sport, dport, payload.Length).CopyTo(packet, headerLen);
    payload.CopyTo(packet, headerLen + 8);
    return packet;
}

static byte[] V6(byte nextHeader, ushort dport, byte[] payload)
{
    var packet = new byte[40 + 8 + payload.Length];
    packet[0] = 0x60;
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4, 2), (ushort)(8 + payload.Length));
    packet[6] = nextHeader;
    packet[7] = 64;
    packet[8] = 0x20;
    packet[23] = 1;
    packet[24] = 0x20;
    packet[39] = 2;
    Udp(50000, dport, payload.Length).CopyTo(packet, 40);
    payload.CopyTo(packet, 48);
    return packet;
}

static byte[] Udp(ushort sport, ushort dport, int payloadLen)
{
    var header = new byte[8];
    BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(0, 2), sport);
    BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(2, 2), dport);
    BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4, 2), (ushort)(8 + payloadLen));
    return header;
}
