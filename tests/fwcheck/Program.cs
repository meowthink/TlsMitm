using System.Net;
using TlsMitm;

// Offline judgement for the inbound reachability check: no driver, no admin, no sockets, nothing here
// opens the firewall COM object or reads this machine's connection table - a suite that did would report
// whatever this host happens to hold instead of what the code decides. What is pinned is the packet the
// probe is made of, the address it comes from, the token it carries, the row that answers it, and the one
// predicate the rule store is allowed to answer (whether a port field names a port).
var failures = new List<string>();

const int RelayPort = 8443;

// --- The probe packet ------------------------------------------------------------------------------
// RFC 791 puts IPv4's protocol number at octet 9 and the two addresses at 12 and 16; RFC 9293 §3.1
// puts TCP's Data Offset in the octet before its flags, counted in 32-bit words. The one case that used
// to be a silent no: a builder that writes the header length and flags two octets late produces a
// packet whose TCP header the stack reads as absent, and the injection still reports success.
var syn = RelayProbe.BuildSyn(IPAddress.Parse("192.0.2.254"), IPAddress.Parse("192.0.2.1"),
                              52999, RelayPort);

Expect(syn.Length == RelayProbe.Length, $"the probe is a header of nothing else, got {syn.Length} octets");
Expect(syn[0] == 0x45, $"IPv4 with a 20-octet header, got {syn[0]:X2}");
Expect(BinaryPrimitives_ReadUInt16(syn, 2) == syn.Length,
    $"total length says the packet's own length, got {BinaryPrimitives_ReadUInt16(syn, 2)}");
Expect(syn[9] == 6, $"protocol is TCP, got {syn[9]}");
Expect(new IPAddress(syn[12..16]).Equals(IPAddress.Parse("192.0.2.254")),
    $"source is the probe's own address, got {new IPAddress(syn[12..16])}");
Expect(new IPAddress(syn[16..20]).Equals(IPAddress.Parse("192.0.2.1")),
    $"destination is the interface the relay listens on, got {new IPAddress(syn[16..20])}");
Expect(BinaryPrimitives_ReadUInt16(syn, 20) == 52999, $"source port carries the token, got {BinaryPrimitives_ReadUInt16(syn, 20)}");
Expect(BinaryPrimitives_ReadUInt16(syn, 22) == RelayPort, $"destination port is the relay, got {BinaryPrimitives_ReadUInt16(syn, 22)}");
Expect((syn[32] >> 4) * 4 == 20, $"Data Offset names a 20-octet TCP header, got octet {syn[32]:X2}");
Expect(syn[33] == 0x02, $"the only flag set is SYN, got {syn[33]:X2}");
Expect(BinaryPrimitives_ReadUInt16(syn, 34) == 64240, $"the window sits where RFC 9293 §3.1 puts it, got {BinaryPrimitives_ReadUInt16(syn, 34)}");
Expect(BinaryPrimitives_ReadUInt16(syn, 36) == 0, "the checksum is left for the driver to fill, got " +
       $"{BinaryPrimitives_ReadUInt16(syn, 36):X4}");

// --- Where the probe comes from --------------------------------------------------------------------
// The address is one below the subnet's last, and the arithmetic has to be the address's own: the uint
// this program reads header fields as holds the octets little-endian, so counting down from it takes
// the first octet off instead of the last.
var lan24 = new LanSide(IPAddress.Parse("192.168.122.1"), IPAddress.Parse("192.168.122.0"),
                        IPAddress.Parse("192.168.122.255"), 5);
Expect(lan24.ProbeAddress.Equals(IPAddress.Parse("192.168.122.254")),
    $"/24 probe source, got {lan24.ProbeAddress}");
var lan16 = new LanSide(IPAddress.Parse("172.16.5.4"), IPAddress.Parse("172.16.0.0"),
                        IPAddress.Parse("172.16.255.255"), 7);
Expect(lan16.ProbeAddress.Equals(IPAddress.Parse("172.16.255.254")),
    $"/16 probe source, got {lan16.ProbeAddress}");
foreach (var side in new[] { lan24, lan16 })
{
    var probe = ToNumber(side.ProbeAddress);
    Expect(probe > ToNumber(side.Network), $"{side.ProbeAddress} is above the {side.Network} network address");
    Expect(side.ProbeAddress.Equals(IPAddress.Parse("127.0.0.1")) == false &&
           !IPAddress.IsLoopback(side.ProbeAddress), $"{side.ProbeAddress} is not a loopback address, so its arrival tests the inbound filter");
    Expect(!side.ProbeAddress.Equals(side.Last) && !side.ProbeAddress.Equals(side.Address),
        $"{side.ProbeAddress} is neither the all-ones address of {side.Last} nor this host's own {side.Address}");
}

// --- The token the probe carries -------------------------------------------------------------------
// Its peer port is what the relay's lookup is keyed on, so a probe that borrowed a token a live flow
// holds would be answered as that flow's connection.
var table = new FlowTable();
var client = ToNumber(IPAddress.Parse("192.0.2.10"));
var server = ToNumber(IPAddress.Parse("198.51.100.7"));
var held = table.Open(FlowTable.KeyV4(client, 60000, server, 443), intercept: true);
var collisions = 0;
var outside = 0;
for (var attempt = 0; attempt < 500; attempt++)
{
    var picked = table.FreeToken();
    if (picked == held.Token) collisions++;
    if (picked is < 49152 or > 65535) outside++;
}
Expect(collisions == 0, $"500 picks never offer the token a live flow holds ({held.Token})");
Expect(outside == 0, $"every pick sits inside RFC 6335 §5.2.1's Dynamic range, {outside} did not");

var full = new FlowTable();
for (var i = 0; i < 65535 - 49152 + 1; i++)
    full.Open(FlowTable.KeyV4(client, unchecked((ushort)(40000 + i)), server, 443), intercept: true);
Expect(full.FreeToken() == 0, $"a pool with no spare token answers the probe with none, got {full.FreeToken()}");

// --- The row the probe's answer is ------------------------------------------------------------------------------
// `ReadTcpTable` is the only part of this that touches the OS, and it is not called here: what is judged
// is the predicate over the bytes it returns. The layout is shared/tcpmib.h's MIB_TCPROW - state, local
// address, local port, remote address, remote port as five DWORDs - and the rows are written here at
// those offsets rather than through anything in TlsMitm, so a decode that agreed with its own writer
// would prove nothing. The port members hold the network-order value: measured against `netstat -ano -p
// tcp` on this host, where the same octets read big-endian give 443 and 80.
const ushort Token = 50000;
var probeAddress = IPAddress.Parse("192.168.122.254");
var lanAddress = IPAddress.Parse("192.168.122.1");

Expect(RelayProbe.Answers(Table(Row(RelayProbe.SynRcvd, "192.168.122.1", RelayPort, "192.168.122.254", Token)),
        probeAddress, Token, lanAddress, RelayPort),
    "a SYN-RECEIVED row for the probe's four fields is an answer");
Expect(!RelayProbe.Answers(Table(Row(5, "192.168.122.1", RelayPort, "192.168.122.254", Token)),
        probeAddress, Token, lanAddress, RelayPort),
    "an ESTABLISHED row is not: the probe never sends the ACK that would make one");
Expect(!RelayProbe.Answers(Table(Row(RelayProbe.SynRcvd, "192.168.122.1", RelayPort, "192.168.122.254", 50001)),
        probeAddress, Token, lanAddress, RelayPort),
    "a half-open row on the neighbouring port belongs to somebody else's SYN");
Expect(!RelayProbe.Answers(Table(Row(RelayProbe.SynRcvd, "192.168.122.1", RelayPort, "192.168.122.100", Token)),
        probeAddress, Token, lanAddress, RelayPort),
    "a real client that happens to hold the same port does not answer for the probe's source address");
Expect(!RelayProbe.Answers(Table(Row(RelayProbe.SynRcvd, "192.168.122.1", 8444, "192.168.122.254", Token)),
        probeAddress, Token, lanAddress, RelayPort),
    "a half-open row on a different local port says nothing about the relay");
Expect(!RelayProbe.Answers(Table(Row(RelayProbe.SynRcvd, "127.0.0.1", RelayPort, "192.168.122.254", Token)),
        probeAddress, Token, lanAddress, RelayPort),
    "a half-open row on the loopback copy of the relay port is a local client, not this host answering a SYN from outside");

var second = Table(Row(RelayProbe.SynRcvd, "192.168.122.1", 135, "0.0.0.0", 0),
                   Row(RelayProbe.SynRcvd, "192.168.122.1", RelayPort, "192.168.122.254", Token));
Expect(RelayProbe.Answers(second, probeAddress, Token, lanAddress, RelayPort),
    "the walk does not stop at the first row");

var swapped = Row(RelayProbe.SynRcvd, "192.168.122.1", RelayPort, "192.168.122.254", Token);
(swapped[8], swapped[9]) = (swapped[9], swapped[8]);
Expect(!RelayProbe.Answers(Table(swapped), probeAddress, Token, lanAddress, RelayPort),
    "the port read little-endian is a different number, so the decode is the measured one");

var lying = Table(Row(RelayProbe.SynRcvd, "192.168.122.1", RelayPort, "192.168.122.254", Token));
BinaryPrimitives_WriteUInt32(lying, 25);
Expect(RelayProbe.Answers(lying, probeAddress, Token, lanAddress, RelayPort),
    "a count larger than the octets that came back is judged on the rows that are physically there");
Expect(!RelayProbe.Answers(lying[..3], probeAddress, Token, lanAddress, RelayPort),
    "a truncated table answers nothing rather than reading past its end");

// --- What a rule's port field can and cannot say ---------------------------------------------------
// A wildcard counts, because a pre-defined service rule's own field is a wildcard while its filter is
// not; that is the reason this predicate is only ever asked for candidates.
Expect(InboundFirewall.CoversPort("*", RelayPort), "'*' is treated as covering the port");
Expect(InboundFirewall.CoversPort("any", RelayPort), "'any' likewise, whatever the casing");
Expect(InboundFirewall.CoversPort("8443", RelayPort), "an exact port covers it");
Expect(InboundFirewall.CoversPort("80,443, 8443", RelayPort), "a list with spaces still names it");
Expect(InboundFirewall.CoversPort("8000-9000", RelayPort), "a range that straddles it covers it");
Expect(InboundFirewall.CoversPort("8443-8443", RelayPort), "a one-port range covers its own endpoint");
Expect(InboundFirewall.CoversPort("443-8443", RelayPort), "a range's upper endpoint counts");
Expect(!InboundFirewall.CoversPort("80", RelayPort), "a different single port does not");
Expect(!InboundFirewall.CoversPort("8444-9000", RelayPort), "a range that starts one above does not");
Expect(!InboundFirewall.CoversPort("84430", RelayPort), "a port that only starts with the digits does not");
Expect(!InboundFirewall.CoversPort("", RelayPort), "an empty field covers nothing");

if (failures.Count > 0)
{
    Console.WriteLine($"[fwcheck] FAIL ({failures.Count})");
    failures.ForEach(Console.WriteLine);
    return 1;
}
Console.WriteLine("[fwcheck] PASS - the probe packet's TCP header length and flags, the probe source in " +
                  "both prefix lengths, a token no flow holds, the table row that answers the probe, and " +
                  "which port fields name the relay port");
return 0;

static ushort BinaryPrimitives_ReadUInt16(byte[] bytes, int offset) =>
    (ushort)(bytes[offset] << 8 | bytes[offset + 1]);

static void BinaryPrimitives_WriteUInt32(byte[] bytes, uint value)
{
    bytes[0] = (byte)value;
    bytes[1] = (byte)(value >> 8);
    bytes[2] = (byte)(value >> 16);
    bytes[3] = (byte)(value >> 24);
}

// One MIB_TCPROW: five DWORDs, the state and the two addresses in the order a machine holds them and the
// two ports as the network-order value the MIB stores in the low half of a DWORD.
static byte[] Row(uint state, string local, int localPort, string remote, int remotePort)
{
    var bytes = new byte[RelayProbe.RowLength];
    BinaryPrimitives_WriteUInt32(bytes, state);
    IPAddress.Parse(local).GetAddressBytes().CopyTo(bytes, 4);
    bytes[8] = (byte)(localPort >> 8);
    bytes[9] = (byte)localPort;
    IPAddress.Parse(remote).GetAddressBytes().CopyTo(bytes, 12);
    bytes[16] = (byte)(remotePort >> 8);
    bytes[17] = (byte)remotePort;
    return bytes;
}

static byte[] Table(params byte[][] rows)
{
    var bytes = new byte[4 + rows.Length * RelayProbe.RowLength];
    BinaryPrimitives_WriteUInt32(bytes, (uint)rows.Length);
    for (var i = 0; i < rows.Length; i++)
        rows[i].CopyTo(bytes, 4 + i * RelayProbe.RowLength);
    return bytes;
}

static uint ToNumber(IPAddress address)
{
    Span<byte> big = stackalloc byte[4];
    address.GetAddressBytes().CopyTo(big);
    return System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(big);
}

void Expect(bool condition, string what)
{
    if (!condition) failures.Add(what);
    Console.WriteLine($"{(condition ? "ok  " : "FAIL")} {what}");
}
