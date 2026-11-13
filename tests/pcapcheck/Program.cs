using System.Buffers.Binary;
using System.Net;
using TlsMitm;

// Offline judgement for the capture writer: write a short dialogue, read the file back, and assert the
// bytes a dissector would see. The point is the sequence/acknowledgement progression - a constant seq
// turns every frame after the first into a "suspected retransmission" and leaves the payload undissected -
// plus the synthesized three-way opening, the ports/addresses, and the checksums Wireshark validates.
var failures = new List<string>();
void Expect(bool ok, string what)
{
    if (!ok) failures.Add(what);
    Console.WriteLine($"{(ok ? "ok  " : "FAIL")} {what}");
}

var client = IPAddress.Parse("192.0.2.10");
var server = IPAddress.Parse("198.51.100.7");
const ushort ClientPort = 50000, ServerPort = 443;

var path = Path.Combine(Path.GetTempPath(), $"pcapcheck-{Environment.ProcessId}.pcap");
using (var writer = new PcapWriter(path))
{
    writer.WritePacket(System.Text.Encoding.ASCII.GetBytes("hello"), true, client, server, ClientPort, ServerPort);
    writer.WritePacket(System.Text.Encoding.ASCII.GetBytes("world"), false, server, client, ServerPort, ClientPort);
}

var file = File.ReadAllBytes(path);
File.Delete(path);

// --- global header -----------------------------------------------------------------------------------
Expect(file.Length > 24, "the file has a global header");
Expect(BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(0)) == 0xa1b2c3d4u, "the magic is the classic pcap magic");
Expect(BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(4)) == 2 && BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(6)) == 4,
    "the version is 2.4");
Expect(BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(20)) == 1, "the link type is Ethernet");

// --- records -----------------------------------------------------------------------------------------
static List<byte[]> Records(byte[] file)
{
    var list = new List<byte[]>();
    var at = 24;
    while (at + 16 <= file.Length)
    {
        var incl = (int)BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(at + 8));
        if (at + 16 + incl > file.Length) break;
        list.Add(file.AsSpan(at + 16, incl).ToArray());
        at += 16 + incl;
    }
    return list;
}

var recs = Records(file);
Expect(recs.Count == 5, $"three handshake segments plus two data records, got {recs.Count}");

// v4 frame: Ethernet 14, IPv4 20, TCP 20, payload at 54.
static ushort Port(byte[] p, int off) => BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(off));
static uint Seq(byte[] p) => BinaryPrimitives.ReadUInt32BigEndian(p.AsSpan(38));
static uint Ack(byte[] p) => BinaryPrimitives.ReadUInt32BigEndian(p.AsSpan(42));
static byte Flags(byte[] p) => p[47];
static byte[] Payload(byte[] p) => p.AsSpan(54).ToArray();
static bool IpIs(byte[] p, int off, IPAddress a) => p.AsSpan(off, 4).SequenceEqual(a.GetAddressBytes());

// The synthesized opening: SYN, SYN-ACK, ACK, with ISN 0 so the first data byte is sequence 1.
Expect(Flags(recs[0]) == 0x02 && Seq(recs[0]) == 0 && Ack(recs[0]) == 0, "the first segment is a SYN at seq 0");
Expect(Flags(recs[1]) == 0x12 && Seq(recs[1]) == 0 && Ack(recs[1]) == 1, "the second is a SYN-ACK acknowledging the SYN");
Expect(Flags(recs[2]) == 0x10 && Seq(recs[2]) == 1 && Ack(recs[2]) == 1, "the third is the ACK that opens the stream");

// The outbound data record.
var outRec = recs[3];
Expect(Port(outRec, 34) == ClientPort && Port(outRec, 36) == ServerPort, "the outbound record carries the client's port pair");
Expect(IpIs(outRec, 26, client) && IpIs(outRec, 30, server), "the outbound record carries the client→server addresses");
Expect(Seq(outRec) == 1 && Ack(outRec) == 1, $"the first data byte is sequence 1, got seq {Seq(outRec)} ack {Ack(outRec)}");
Expect(Payload(outRec).AsSpan(0, 5).SequenceEqual(System.Text.Encoding.ASCII.GetBytes("hello")), "the outbound payload is intact");

// The inbound data record: its ack must have advanced by the outbound payload length.
var inRec = recs[4];
Expect(Port(inRec, 34) == ServerPort && Port(inRec, 36) == ClientPort, "the inbound record carries the server's port pair");
Expect(IpIs(inRec, 26, server) && IpIs(inRec, 30, client), "the inbound record carries the server→client addresses");
Expect(Seq(inRec) == 1 && Ack(inRec) == 6, $"the inbound ack advances past the outbound bytes, got seq {Seq(inRec)} ack {Ack(inRec)}");
Expect(Payload(inRec).AsSpan(0, 5).SequenceEqual(System.Text.Encoding.ASCII.GetBytes("world")), "the inbound payload is intact");

// The IPv4 header checksum must add up to zero (RFC 1071), or Wireshark marks every frame bad.
static ushort Fold(ulong sum) { while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16); return (ushort)~sum; }
static bool IpChecksumOk(byte[] p)
{
    ulong sum = 0;
    for (var i = 14; i < 34; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(i));
    return Fold(sum) == 0;
}
Expect(IpChecksumOk(outRec) && IpChecksumOk(inRec), "the IPv4 header checksums validate");

if (failures.Count > 0)
{
    Console.WriteLine($"[pcapcheck] FAIL ({failures.Count})");
    return 1;
}
Console.WriteLine("[pcapcheck] PASS - pcap global header, synthesized handshake, seq/ack progression, ports/addresses, checksums");
return 0;
