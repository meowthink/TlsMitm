using System.Buffers.Binary;
using System.Net;
using Router;

// Offline judgement for RFC 6146's stateful NAT64: no driver, no admin, no socket, and no clock of its own.
// Each case lays one datagram out octet by octet, hands it to the table, and asserts what came back - the
// addresses and ports of the outgoing 5-tuple, what the two tables settled on, and the clause a discard cites.
// Every checksum is computed a second time from the standard's own figure (RFC 791 §3.1, RFC 9293 §3.1's
// figure 2, RFC 8200 §8.1, RFC 1624 §2) and every header is parsed here rather than with Siit's reader, so a
// mistake Nat64.cs and Siit.cs share cannot agree with a copy of itself.

var failures = new List<string>();
var notes = new List<string>();

void Expect(bool ok, string what)
{
    if (ok) notes.Add($"ok {what}");
    else failures.Add(what);
}

// A discard has to name the clause it obeys; an unexplained one is indistinguishable from a dropped packet.
bool Discards(Nat64Outcome outcome, string because) =>
    outcome.Action == Nat64Action.Discard && outcome.Packet is null &&
    outcome.Reason is not null && outcome.Reason.Contains(because, StringComparison.Ordinal);

bool Left(Nat64Outcome outcome) => outcome.Action == Nat64Action.None;
bool Forwarded(Nat64Outcome outcome) => outcome.Action == Nat64Action.Translate && outcome.Packet is not null;

var pref = new Pref64Config(IPAddress.Parse("64:ff9b::"), 96);
const string Wan = "203.0.113.9";
const string Wan2 = "203.0.113.33";
const string Server = "198.51.100.7";
const string Server2 = "198.51.100.8";
const string Stranger = "198.51.100.9";
const string ClientA = "2001:db8::11";
const string ClientB = "2001:db8::12";
var path = new Siit.PathMtu(1492, 1492);
var none = Array.Empty<byte>();
var eight = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

// RFC 6052 §5's /96: the IPv4 address is the last four octets, laid out here rather than with Pref64.Embed.
string E6(string v4) => $"64:ff9b::{v4}";
byte[] Addr(string address) => IPAddress.Parse(address).GetAddressBytes();
bool Is(byte[] address, string other) => address.SequenceEqual(Addr(other));
ushort U16(byte[] data, int at) => BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(at));

var clock = new Clock();

Nat64 NewNat(TimeSpan? udpLifetime = null, Func<byte, ICollection<ushort>>? localPorts = null,
    Func<byte, ICollection<ushort>>? otherMapped = null, string wanAddress = Wan) =>
    new(pref, IPAddress.Parse(wanAddress), () => clock.Now, udpLifetime, localPorts, otherMapped);

// RFC 1071 §1's sum, and the property §1(B) states with it: a message whose checksum field is correct sums,
// that field read as it stands, to all ones.
uint Folded(params byte[][] parts)
{
    var all = new List<byte>();
    foreach (var part in parts) all.AddRange(part);
    var sum = 0u;
    for (var i = 0; i < all.Count; i += 2)
    {
        var word = (uint)all[i] << 8;
        if (i + 1 < all.Count) word |= all[i + 1];
        sum += word;
    }
    while (sum > 0xFFFF) sum = (sum & 0xFFFF) + (sum >> 16);
    return sum;
}

ushort Ones(params byte[][] parts) => (ushort)~Folded(parts);
bool ChecksumOk(params byte[][] parts) => Folded(parts) == 0xFFFF;

// RFC 9293 §3.1's figure 2 and RFC 8200 §8.1's: the two pseudo-headers a transport checksum runs over.
byte[] Pseudo4(byte[] source, byte[] destination, byte protocol, int length)
{
    var pseudo = new byte[12];
    source.CopyTo(pseudo, 0);
    destination.CopyTo(pseudo, 4);
    pseudo[9] = protocol;
    BinaryPrimitives.WriteUInt16BigEndian(pseudo.AsSpan(10), (ushort)length);
    return pseudo;
}

byte[] Pseudo6(byte[] source, byte[] destination, byte nextHeader, int length)
{
    var pseudo = new byte[40];
    source.CopyTo(pseudo, 0);
    destination.CopyTo(pseudo, 16);
    BinaryPrimitives.WriteUInt32BigEndian(pseudo.AsSpan(32), (uint)length);
    pseudo[39] = nextHeader;
    return pseudo;
}

// RFC 1624 §2's "HC' = ~(C + (-m) + m')", which is how a checksum is moved when one of the words the sender
// summed changes and the rest of the message is not on hand.
ushort Move(ushort stored, ushort oldWord, ushort newWord)
{
    var sum = (uint)(ushort)~stored + (uint)(ushort)~oldWord + newWord;
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    return (ushort)~(ushort)sum;
}

byte[] UdpSeg(string source, string destination, bool v6, ushort sport, ushort dport, byte[] data,
    ushort? checksum = null)
{
    var src = Addr(source);
    var dst = Addr(destination);
    var seg = new byte[8 + data.Length];
    BinaryPrimitives.WriteUInt16BigEndian(seg.AsSpan(0), sport);
    BinaryPrimitives.WriteUInt16BigEndian(seg.AsSpan(2), dport);
    BinaryPrimitives.WriteUInt16BigEndian(seg.AsSpan(4), (ushort)seg.Length);
    data.CopyTo(seg.AsSpan(8));
    var pseudo = v6 ? Pseudo6(src, dst, 17, seg.Length) : Pseudo4(src, dst, 17, seg.Length);
    BinaryPrimitives.WriteUInt16BigEndian(seg.AsSpan(6), checksum ?? Ones(pseudo, seg));
    return seg;
}

byte[] TcpSeg(string source, string destination, bool v6, ushort sport, ushort dport, byte flags, byte[] data)
{
    var src = Addr(source);
    var dst = Addr(destination);
    var seg = new byte[20 + data.Length];
    BinaryPrimitives.WriteUInt16BigEndian(seg.AsSpan(0), sport);
    BinaryPrimitives.WriteUInt16BigEndian(seg.AsSpan(2), dport);
    BinaryPrimitives.WriteUInt32BigEndian(seg.AsSpan(4), 1);
    BinaryPrimitives.WriteUInt32BigEndian(seg.AsSpan(8), 0);
    seg[12] = 0x50;
    seg[13] = flags;
    BinaryPrimitives.WriteUInt16BigEndian(seg.AsSpan(14), 65535);
    data.CopyTo(seg.AsSpan(20));
    var pseudo = v6 ? Pseudo6(src, dst, 6, seg.Length) : Pseudo4(src, dst, 6, seg.Length);
    BinaryPrimitives.WriteUInt16BigEndian(seg.AsSpan(16), Ones(pseudo, seg));
    return seg;
}

// RFC 792 §1's and RFC 4443 §2.3's message: eight octets of header, the second word its Type names, then the
// quoted datagram and whatever sits behind it.
byte[] Icmp4(byte type, byte code, byte[] second, byte[] body)
{
    var message = new byte[8 + body.Length];
    message[0] = type;
    message[1] = code;
    second.CopyTo(message, 4);
    body.CopyTo(message, 8);
    BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(2), Ones(message));
    return message;
}

byte[] Icmp6(byte type, byte code, byte[] second, byte[] body, string source, string destination)
{
    var message = new byte[8 + body.Length];
    message[0] = type;
    message[1] = code;
    second.CopyTo(message, 4);
    body.CopyTo(message, 8);
    BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(2),
        Ones(Pseudo6(Addr(source), Addr(destination), 58, message.Length), message));
    return message;
}

byte[] IdSeq(ushort identifier, ushort sequence) => [(byte)(identifier >> 8), (byte)identifier, (byte)(sequence >> 8), (byte)sequence];

byte[] V4(byte protocol, string source, string destination, byte[] transport, ushort id = 0x4000,
    ushort flags = 0, byte ttl = 64)
{
    var packet = new byte[20 + transport.Length];
    packet[0] = 0x45;
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), (ushort)packet.Length);
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4), id);
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(6), flags);
    packet[8] = ttl;
    packet[9] = protocol;
    Addr(source).CopyTo(packet.AsSpan(12));
    Addr(destination).CopyTo(packet.AsSpan(16));
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(10), Ones(packet[..20]));
    transport.CopyTo(packet.AsSpan(20));
    return packet;
}

byte[] V6(byte next, string source, string destination, byte[] payload, byte hopLimit = 8)
{
    var packet = new byte[40 + payload.Length];
    packet[0] = 0x60;
    packet[6] = next;
    packet[7] = hopLimit;
    Addr(source).CopyTo(packet.AsSpan(8));
    Addr(destination).CopyTo(packet.AsSpan(24));
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4), (ushort)payload.Length);
    payload.CopyTo(packet.AsSpan(40));
    return packet;
}

// RFC 8200 §4.5's header: the next header it names, the 13-bit offset in 8-octet units with the M flag after
// it, and the 32-bit Identification.
byte[] FragHead(byte next, int offsetUnits, bool more, uint id)
{
    var header = new byte[8];
    header[0] = next;
    BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(2), (ushort)((offsetUnits << 3) | (more ? 1 : 0)));
    BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4), id);
    return header;
}

bool MoreFragments(ushort flags) => (flags & 0x2000) != 0;

// --- the parsers, written from RFC 791 §3.1 and RFC 8200 §3 rather than from the product's reader ----------

// Parsing the packet an outcome carried stops here when it carried none, because a null dereference would kill
// the run before the report and leave the clause the table cited unread.
Nat64Outcome Have(Nat64Outcome outcome)
{
    if (outcome.Packet is null)
    {
        Console.WriteLine($"stopped: an outcome was read for its packet but carried none - action {outcome.Action}, reason {outcome.Reason ?? "none given"}");
        Console.WriteLine($"assertions before the stop: {notes.Count + failures.Count}, of them failing {failures.Count}");
        foreach (var f in failures) Console.WriteLine($"FAIL {f}");
        Environment.Exit(2);
    }
    return outcome;
}

P4 Read4(Nat64Outcome outcome) => Parse4(Have(outcome).Packet!);
P6 Read6(Nat64Outcome outcome) => Parse6(Have(outcome).Packet!);

P4 Parse4(byte[] packet)
{
    var ihl = (packet[0] & 0x0F) * 4;
    var total = U16(packet, 2);
    var flags = U16(packet, 6);
    return new P4(packet[12..16], packet[16..20], packet[9], ihl, U16(packet, 4), MoreFragments(flags),
        flags & 0x1FFF, ChecksumOk(packet[..ihl]), packet[8], packet[ihl..Math.Min(total, packet.Length)]);
}

P6 Parse6(byte[] packet)
{
    var payload = U16(packet, 4);
    var next = packet[6];
    var at = 40;
    var fragmented = next == 44;
    byte fragNext = next;
    var offset = 0;
    var more = false;
    uint id = 0;
    if (fragmented)
    {
        fragNext = packet[40];
        var word = U16(packet, 42);
        offset = word >> 3;
        more = (word & 1) != 0;
        id = BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(44));
        at = 48;
    }
    return new P6(packet[8..24], packet[24..40], next, at, fragmented, fragNext, offset, more, id, packet[7],
        packet[at..Math.Min(40 + payload, packet.Length)]);
}

// The one IPv6 datagram every IPv6 case starts from.
var udpRequest = V6(17, ClientA, E6(Server), UdpSeg(ClientA, E6(Server), true, 4000, 443, eight));

// --- §3.5's filters and §3.4's two protocol gates ---------------------------------------------------------------------

{
    var t = NewNat();
    var fromPrefix = t.Translate(V6(17, E6(Server), E6(Server2),
        UdpSeg(E6(Server), E6(Server2), true, 4000, 443, eight)), path);
    Expect(Discards(fromPrefix, "source address that contains the Pref64::/n"),
        "§3.5: an IPv6 packet sourced from the prefix is the one that would loop a hairpin, and it is discarded before any table is read");
    Expect(t.Filtered == 1 && t.BindingCount == 0, "the discard is counted, and it creates nothing");

    Expect(Left(t.Translate(V6(17, ClientA, "2001:db8::99",
        UdpSeg(ClientA, "2001:db8::99", true, 4000, 443, eight)), path)),
        "§3.5: a destination outside the prefix is \"MUST only process\" in the negative - the packet is not this table's, and the caller keeps forwarding it");
    Expect(Left(t.Translate(V4(17, Server, Stranger, UdpSeg(Server, Stranger, false, 443, 4000, eight)), path)),
        "§3.5: an IPv4 packet whose destination is not in the pool this table answers on is left alone too");

    Expect(Discards(t.Translate(V6(132, ClientA, E6(Server), eight), path), "SHOULD be discarded"),
        "§3.4: an IPv6 packet whose last Next Header is neither TCP, UDP nor ICMPv6 \"SHOULD be discarded\", and the ICMPv6 Code 4 beside it is offered only \"if the security policy permits\"");
    Expect(Discards(t.Translate(V4(132, Server, Wan, eight), path), "SHOULD be discarded"),
        "§3.4: the same for an IPv4 Protocol that is neither TCP, UDP nor ICMPv4, where the companion message is an ICMPv4 Code 2");
    Expect(t.NoBinding == 2, "both gates are counted as no binding, not as a filter");
    Expect(Left(t.Translate(new byte[0], path)) && Left(t.Translate([0x50, 0, 0, 0], path)),
        "a buffer that is empty or holds neither version this translator reads is not its business at all");
}

// --- §3.5.1's UDP, the BIB and the session ------------------------------------------------------------------------------

{
    var t = NewNat();
    var o = t.Translate(udpRequest, path);
    var out4 = Read4(o);
    Expect(Forwarded(o), "§3.3's five steps run on a client's first UDP datagram: tuple, filter, outgoing 5-tuple, translation");
    Expect(out4.Proto == 17 && Is(out4.Src, Wan) && Is(out4.Dst, Server),
        "§3.6.1: the source becomes the binding's (T,t) and the destination \"computed algorithmically from D'\" - the peer's own address out of the prefix");
    Expect(out4.Sport == Nat64.PortFirst && out4.Dport == 443,
        "§3.5.1.1: the client's port 4000 is below this table's floor, so the first free port of the range it can be answered on is bound instead");
    Expect(out4.HeaderOk, "RFC 791 §3.1's header checksum on the datagram this translation wrote");
    Expect(ChecksumOk(Pseudo4(out4.Src, out4.Dst, 17, out4.Body.Length), out4.Body),
        "§3.7's first modification \"note that the TCP and UDP checksum covers the pseudo-header\", recomputed over the new pair");
    Expect(out4.Ttl == 7, "§5.1's Hop Limit decrement carried through one family over");
    Expect(t.BindingCount == 1 && t.SessionCount == 1, "one BIB entry and one STE entry (§3.2's two tables)");
    Expect(t.IsMappedPort(17, Nat64.PortFirst) && t.MappedPorts(17).Count == 1 && t.MappedPorts(6).Count == 0,
        "the port is this table's to claim, and only for UDP - §3.5.1.1's last bullet allows the same number in another BIB");

    var r = t.Translate(V4(17, Server, Wan, UdpSeg(Server, Wan, false, 443, Nat64.PortFirst, eight)), path);
    var out6 = Read6(r);
    Expect(Forwarded(r), "the answer to that datagram finds its session (§3.5.1's IPv4 leg)");
    Expect(out6.Next == 17 && Is(out6.Src, E6(Server)) && Is(out6.Dst, ClientA),
        "§3.6.1: \"The outgoing source transport address is generated from S using the address transformation\", and the BIB holds the destination");
    Expect(out6.Sport == 443 && out6.Dport == 4000,
        "§3.2's invariant that the STE destination IPv4 port is \"set to y, i.e. the same port as the STE destination IPv6 transport address\" is what lets the client's own port be the destination here");
    Expect(ChecksumOk(Pseudo6(out6.Src, out6.Dst, 17, out6.Body.Length), out6.Body),
        "RFC 8200 §8.1's pseudo-header for the UDP checksum of the packet that goes back to the client");
    Expect(t.Translated64 == 1 && t.Translated46 == 1, "one translation each way");
    Expect(t.OwnsDatagram(V4(17, Server, Wan, UdpSeg(Server, Wan, false, 443, Nat64.PortFirst, eight))) &&
           !t.OwnsDatagram(V4(17, Server, Wan, UdpSeg(Server, Wan, false, 443, 60000, eight))) &&
           !t.OwnsDatagram(V4(17, Server, Stranger, UdpSeg(Server, Stranger, false, 443, Nat64.PortFirst, eight))),
        "the reply dispatch asks the same reverse key the reply leg uses, on the destination port and the pool address");

    var filtered = t.Translate(V4(17, Stranger, Wan, UdpSeg(Stranger, Wan, false, 5555, Nat64.PortFirst, eight)), path);
    Expect(Discards(filtered, "Address-Dependent Filtering"),
        "§3.5.1: with Address-Dependent Filtering the destination IPv4 address must be one the client sent to, and \"Otherwise, the packet is discarded\"");
    Expect(t.Filtered == 1, "and the filter is counted apart from the missing binding");

    var newPort = t.Translate(V4(17, Server, Wan, UdpSeg(Server, Wan, false, 5555, Nat64.PortFirst, eight)), path);
    Expect(Forwarded(newPort) && Read6(newPort).Sport == 5555 && t.SessionCount == 2,
        "§3.5.1's two searches are different: the filter compares the destination IPv4 address, the entry the whole transport address, so the same host on a new port passes the filter and gets its own session");

    var noBib = t.Translate(V4(17, Server, Wan, UdpSeg(Server, Wan, false, 443, 60000, eight)), path);
    Expect(Discards(noBib, "MUST be dropped"),
        "§3.5.1: an IPv4 packet whose destination transport address has no UDP BIB entry \"MUST be dropped\"");
    Expect(t.NoBinding == 1 && t.SessionCount == 2, "and that drop is the missing-binding count, not the filter's");
}

{
    var t = NewNat();
    t.Translate(udpRequest, path);
    t.Translate(V4(17, Server, Wan, UdpSeg(Server, Wan, false, 443, Nat64.PortFirst, eight)), path);
    clock.Advance((int)Nat64.UdpDefault.TotalSeconds - 30);
    t.Sweep();
    Expect(t.SessionCount == 1 && t.BindingCount == 1,
        $"§3.5.1's UDP_DEFAULT ({Nat64.UdpDefault.TotalMinutes:0} minutes) is the lifetime, and 30 seconds short of it the session is still there");
    clock.Advance(60);
    t.Sweep();
    Expect(t.SessionCount == 0 && t.BindingCount == 0 && t.IsMappedPort(17, Nat64.PortFirst) == false,
        "§3.1: \"Dynamically created entries are deleted from the corresponding BIB when the last session associated with the BIB entry is removed from the session table\"");

    var shortLived = NewNat(udpLifetime: TimeSpan.FromMinutes(2));
    shortLived.Translate(udpRequest, path);
    clock.Advance(125);
    shortLived.Sweep();
    Expect(shortLived.SessionCount == 0,
        "and the lifetime is configurable down to that floor: --udp-timeout 2 ages the same flow in 2 minutes");
}

{
    var threw = false;
    try { NewNat(udpLifetime: TimeSpan.FromMinutes(1)); }
    catch (ArgumentOutOfRangeException) { threw = true; }
    Expect(threw, "§3.5.1: \"The maximum session lifetime MUST NOT be less than UDP_MIN\", and the constructor refuses one");
}

// --- §3.5.1.1's allocation rules ----------------------------------------------------------------------------------------

{
    var t = NewNat();
    var preferred = t.Translate(V6(17, ClientA, E6(Server), UdpSeg(ClientA, E6(Server), true, 50000, 443, eight)), path);
    Expect(Read4(preferred).Sport == 50000,
        "§3.5.1.1: \"If the port s is in the range 1024-65535, and the NAT64 has an available port t in the same port range, then the NAT64 SHOULD allocate the port t\"");

    var odd = t.Translate(V6(17, ClientB, E6(Server), UdpSeg(ClientB, E6(Server), true, 4001, 443, eight)), path);
    Expect((Read4(odd).Sport & 1) == 1 && Read4(odd).Sport != 4001,
        "§3.5.1.1: \"The NAT64 SHOULD preserve the port parity (odd/even), as per Section 4.2.2 of [RFC4787])\", and the client's own port is below the range the reply leg can see");

    var busy = new HashSet<ushort> { Nat64.PortFirst };
    var localOnly = NewNat(localPorts: protocol => protocol == 17 ? busy : new HashSet<ushort>());
    var moved = localOnly.Translate(udpRequest, path);
    Expect(Read4(moved).Sport == (ushort)(Nat64.PortFirst + 2),
        "the host's own socket is not one to bind over: the next port of the same parity is taken instead");

    var mapped4 = new HashSet<ushort> { Nat64.PortFirst, (ushort)(Nat64.PortFirst + 2) };
    var otherOnly = NewNat(otherMapped: protocol => protocol == 17 ? mapped4 : new HashSet<ushort>());
    Expect(Read4(otherOnly.Translate(udpRequest, path)).Sport == (ushort)(Nat64.PortFirst + 4),
        "and so is a port the same host's IPv4 NAT already mapped - the two tables exchange their views so neither takes the other's traffic");

    var all = new HashSet<ushort>(Enumerable.Range(0, 0x10000).Select(port => (ushort)port));
    var exhausted = NewNat(localPorts: _ => all);
    var o = exhausted.Translate(udpRequest, path);
    Expect(Discards(o, "not possible to allocate"),
        "§3.5.1.1: \"If it is not possible to allocate an appropriate IPv4 transport address or create a BIB entry, then the packet is discarded\", with the ICMPv6 Code 3 beside it only a SHOULD");
    Expect(exhausted.BindingCount == 0 && exhausted.Exhausted == 1,
        "and a binding that got no port is not put in the table for the next packet to answer from");

    var shared = NewNat();
    var overUdp = shared.Translate(udpRequest, path);
    var overTcp = shared.Translate(V6(6, ClientA, E6(Server), TcpSeg(ClientA, E6(Server), true, 4000, 443, 0x02, none)), path);
    Expect(Read4(overUdp).Sport == Read4(overTcp).Sport,
        "§3.5.1.1's last bullet in the other direction: the allocated address \"MUST NOT be in use in another entry in the same BIB, but can be in use in other BIBs (e.g., the UDP and TCP BIBs)\"");
    Expect(shared.IsMappedPort(17, Nat64.PortFirst) && shared.IsMappedPort(6, Nat64.PortFirst),
        "and the two are told apart by the protocol in the key, which is why the reply dispatch asks it");
}

// --- §3.5.2's TCP machine -----------------------------------------------------------------------------------------------

{
    var t = NewNat();
    var bare = t.Translate(V6(6, ClientA, E6(Server), TcpSeg(ClientA, E6(Server), true, 4000, 443, 0x10, none)), path);
    Expect(Discards(bare, "no corresponding entry in the TCP BIB"),
        "§3.5.2's CLOSED row: \"If there is no corresponding entry in the TCP BIB, the packet is silently discarded\"");
    Expect(t.BindingCount == 0 && t.SessionCount == 0,
        "and no binding is made for it, so a packet that is not a SYN cannot spend a port on a flow nothing can answer");

    var syn = t.Translate(V6(6, ClientA, E6(Server), TcpSeg(ClientA, E6(Server), true, 4000, 443, 0x02, none)), path);
    var mapped = Read4(syn).Sport;
    Expect(Forwarded(syn) && Read4(syn).Proto == 6 && Read4(syn).Body[13] == 0x02,
        "§3.5.2's CLOSED row 2: a SYN from IPv6 makes the binding, the session, and a translated SYN on the IPv4 side");
    Expect(t.BindingCount == 1 && t.SessionCount == 1, "one BIB entry and one session in V6 INIT");

    var again = t.Translate(V6(6, ClientA, E6(Server), TcpSeg(ClientA, E6(Server), true, 4000, 443, 0x02, none)), path);
    Expect(Forwarded(again) && t.BindingCount == 1 && t.MappedPorts(6).Count == 1,
        "§3.5.2.2's V6 INIT row keeps the state and the mapped port against a retransmitted SYN");

    // A non-SYN to a peer the client never opened with: the CLOSED row asks the BIB, and the state it names is unchanged.
    var sideways = t.Translate(V6(6, ClientA, E6(Server2), TcpSeg(ClientA, E6(Server2), true, 4000, 8443, 0x10, none)), path);
    Expect(Forwarded(sideways) && t.SessionCount == 1,
        "§3.5.2's CLOSED row for \"any other packet belonging to this connection\": \"the packet SHOULD be translated and forwarded ... The state remains unchanged\", and it is the BIB that is asked, not a session");

    clock.Advance(180);
    var ack = t.Translate(V4(6, Server, Wan, TcpSeg(Server, Wan, false, 443, mapped, 0x12, none)), path);
    Expect(Forwarded(ack) && Read6(ack).Dport == 4000,
        "§3.5.2.2's V6 INIT row: a V4 SYN packet moves the session to ESTABLISHED with the maximum session lifetime");
    clock.Advance((int)Nat64.TcpTransitory.TotalSeconds + 60);
    t.Sweep();
    Expect(t.SessionCount == 1 && t.BindingCount == 1,
        $"and ESTABLISHED is armed with TCP_EST plus TCP_TRANS ({Nat64.TcpEstablished.TotalMinutes:0} minutes), not the {Nat64.TcpTransitory.TotalMinutes}-minute timer V6 INIT had");

    var midstream = t.Translate(V6(6, ClientA, E6(Server), TcpSeg(ClientA, E6(Server), true, 4000, 443, 0x10, none)), path);
    Expect(Forwarded(midstream), "§3.5.2.2's ESTABLISHED row: \"Any other packet ... the state remains ESTABLISHED\" and the timer is reset");

    var fin6 = TcpSeg(ClientA, E6(Server), true, 4000, 443, 0x01, none);
    t.Translate(V6(6, ClientA, E6(Server), fin6), path);
    Expect(t.SessionCount == 1, "§3.5.2.2: an ESTABLISHED session that sees a V6 FIN moves to V6 FIN RCV");
    var secondFin6 = t.Translate(V6(6, ClientA, E6(Server), fin6), path);
    Expect(Forwarded(secondFin6), "and it forwards the second one, which is what the state's own row asks");
    clock.Advance((int)Nat64.TcpTransitory.TotalSeconds + 10);
    t.Sweep();
    Expect(t.SessionCount == 1 && t.BindingCount == 1,
        "§3.5.2.2's V6 FIN RCV row names \"a V4 FIN packet\" as the one that closes the half, and \"any packet other than the V4 FIN ... The state remains unchanged as V6 FIN RCV\" with the maximum lifetime - so a second V6 FIN neither reaches BOTH FIN RCV nor leaves the 4 minutes it arrived with, and 250 seconds of silence cannot reap it");

    var fin4 = t.Translate(V4(6, Server, Wan, TcpSeg(Server, Wan, false, 443, mapped, 0x01, none)), path);
    Expect(Forwarded(fin4), "§3.5.2.2: the V4 FIN the state was waiting for moves it to BOTH FIN RCV");
    clock.Advance((int)Nat64.TcpTransitory.TotalSeconds + 10);
    t.Sweep();
    Expect(t.SessionCount == 0 && t.BindingCount == 0,
        "and BOTH FIN RCV has no way back out: §3.5.2.2's row for it is \"All packets are translated and forwarded\" beside \"If the lifetime expires, the Session Table Entry is deleted and the state is moved to CLOSED\", and no packet of this connection ever arrived to rearm the TCP_TRANS timer it entered with");
}

{
    var t = NewNat();
    var syn = t.Translate(V6(6, ClientA, E6(Server), TcpSeg(ClientA, E6(Server), true, 4000, 443, 0x02, none)), path);
    var mapped = Read4(syn).Sport;
    t.Translate(V4(6, Server, Wan, TcpSeg(Server, Wan, false, 443, mapped, 0x12, none)), path);

    t.Translate(V6(6, ClientA, E6(Server), TcpSeg(ClientA, E6(Server), true, 4000, 443, 0x04, none)), path);
    Expect(t.Translate(V4(6, Server, Wan, TcpSeg(Server, Wan, false, 443, mapped, 0x10, none)), path) is { Action: Nat64Action.Translate },
        "§3.5.2.2's ESTABLISHED row for a RST: the packet is translated, and the state the section gives is TRANS");
    clock.Advance((int)Nat64.TcpTransitory.TotalSeconds - 60);
    t.Translate(V6(6, ClientA, E6(Server), TcpSeg(ClientA, E6(Server), true, 4000, 443, 0x10, none)), path);
    clock.Advance(120);
    t.Sweep();
    Expect(t.SessionCount == 1,
        "§3.5.2.2's TRANS row: \"Any packet other than a RST packet received will move the state back to ESTABLISHED\" - the ACK three minutes in did that, and its own timer is why 2 minutes later the session is still standing");

    clock.Advance((int)Nat64.TcpEstablished.TotalSeconds);
    t.Sweep();
    Expect(t.IsMappedPort(6, mapped),
        "§3.5.2.2's ESTABLISHED expiry: \"the NAT64 SHOULD send a probe packet to refresh the connection ... The state is moved to TRANS\" - the probe is a packet this table does not originate, so the state moves and the binding is still held");
    // §3.5.2.2's TRANS row moves the state back to ESTABLISHED for "a packet other than a RST packet", so a RST is
    // the one probe that asks whether the entry still answers without taking it out of the short timer.
    Expect(t.Translate(V4(6, Server, Wan, TcpSeg(Server, Wan, false, 443, mapped, 0x04, none)), path)
        is { Action: Nat64Action.Translate }, "and the flow still answers for the window TCP_TRANS gives the state");
    clock.Advance((int)Nat64.TcpTransitory.TotalSeconds + 10);
    t.Sweep();
    Expect(t.SessionCount == 0 && t.BindingCount == 0 && !t.IsMappedPort(6, mapped),
        "and TRANS's own expiry is the one that deletes it - §3.5.2.2: \"If the lifetime expires, the Session Table Entry is deleted and the state is moved to CLOSED\" - four minutes after the silence rather than at the end of the two hours");
}

{
    var t = NewNat();
    t.Translate(V6(6, ClientA, E6(Server), TcpSeg(ClientA, E6(Server), true, 4000, 443, 0x02, none)), path);
    clock.Advance((int)Nat64.TcpTransitory.TotalSeconds + 10);
    t.Sweep();
    Expect(t.BindingCount == 0 && t.SessionCount == 0,
        "§3.5.2's CLOSED row 3 arms a new session at TCP_TRANS, so a SYN that never got its V4 SYN is aged out in 4 minutes");
    Expect(Discards(t.Translate(V4(6, Server, Wan, TcpSeg(Server, Wan, false, 443, Nat64.PortFirst, 0x10, none)), path),
        "silently dropping"), "and the externally initiated connection that follows it finds no binding to answer from");
}

// --- §3.5.3's ICMP queries ----------------------------------------------------------------------------------------------

{
    var t = NewNat();
    var ping = t.Translate(V6(58, ClientA, E6(Server), Icmp6(128, 0, IdSeq(7, 1), eight, ClientA, E6(Server))), path);
    var out4 = Read4(ping);
    Expect(Forwarded(ping) && out4.Proto == 1,
        "§3.6.1: \"When translating from IPv6 ICMP to IPv4 ICMP, the protocol number in the protocol field of the IP header is set to 1 (ICMP)\"");
    Expect(out4.Body[0] == 8 && U16(out4.Body, 4) == 7 && U16(out4.Body, 6) == 1,
        "§5.2: \"Echo Request and Echo Reply (Type 128 and 129): Adjust the Type values to 8 and 0\", and RFC 792 §1.9's Identifier and Sequence keep their words");
    Expect(ChecksumOk(out4.Body),
        "§5.2's \"adjust the ICMP checksum both to take the type change into account and to exclude the ICMPv6 pseudo-header\" - RFC 792 §1's message has none");
    Expect(t.BindingCount == 1 && t.SessionCount == 1 && t.IsMappedPort(1, 7),
        "§3.5.3's BIB for the query holds the ICMPv4 Identifier the client's own value could be, since nothing else has it");

    var pong = t.Translate(V4(1, Server, Wan, Icmp4(0, 0, IdSeq(7, 1), eight)), path);
    var out6 = Read6(pong);
    Expect(Forwarded(pong) && out6.Next == 58 && out6.Body[0] == 129 && U16(out6.Body, 4) == 7,
        "§4.2 turns the Echo Reply back into Type 129, and §3.6.2's search by (D,i2) gives the client's own identifier back");
    Expect(Is(out6.Src, E6(Server)) && Is(out6.Dst, ClientA),
        "§3.6.2: the source is generated from the address and the destination comes from the BIB");
    Expect(ChecksumOk(Pseudo6(out6.Src, out6.Dst, 58, out6.Body.Length), out6.Body),
        "§4.2: \"All ICMPv4 messages that are to be translated require that the ICMPv6 checksum field be calculated as part of the translation since ICMPv6, unlike ICMPv4, has a pseudo-header checksum just like UDP and TCP\"");

    clock.Advance((int)Nat64.IcmpQueryLifetime.TotalSeconds + 1);
    t.Sweep();
    Expect(t.BindingCount == 0 && !t.IsMappedPort(1, 7),
        "§3.5.3's ICMP_DEFAULT is 60 seconds, and the binding goes with the session (§3.1)");
}

{
    var held = new HashSet<ushort> { 7 };
    var t = NewNat(localPorts: protocol => protocol == 1 ? held : new HashSet<ushort>());
    var ping = t.Translate(V6(58, ClientA, E6(Server), Icmp6(128, 0, IdSeq(7, 1), eight, ClientA, E6(Server))), path);
    var bound = U16(Read4(ping).Body, 4);
    Expect(bound != 7 && (bound & 1) == 1,
        "§3.5.3 asks for \"any available value ... as the BIB ICMPv4 Identifier\", and this host's own ICMP stack holding 7 means the parity of the client's value is kept on the next free one");
    var pong = t.Translate(V4(1, Server, Wan, Icmp4(0, 0, IdSeq(bound, 1), eight)), path);
    Expect(Forwarded(pong) && U16(Read6(pong).Body, 4) == 7,
        "and the answer is turned back into the identifier the client asked with, which is what lets a ping on the other side of the prefix work at all");
}

{
    var t = NewNat();
    t.Translate(V6(58, ClientA, E6(Server), Icmp6(128, 0, IdSeq(7, 1), eight, ClientA, E6(Server))), path);
    Expect(Discards(t.Translate(V4(1, Server, Wan, Icmp4(0, 0, IdSeq(4000, 1), eight)), path),
        "no ICMP Query BIB entry"),
        "§3.5.3: an Echo Reply whose (IPv4 address, Identifier) pair is in no binding \"is dropped\", and this one is of the right type for §3.4's Query bullet, so it is the stateful lookup that stops it rather than the type gate");
}

{
    var t = NewNat();
    Expect(Discards(t.Translate(V6(58, ClientA, E6(Server), Icmp6(130, 0, IdSeq(7, 1), eight, ClientA, E6(Server))), path),
        "Single-hop message"),
        "§5.2: MLD and Neighbor Discovery types are a \"Single-hop message. Silently drop\", and the gate runs before the allocation so they spend neither an identifier nor a session");
    Expect(t.BindingCount == 0 && t.SessionCount == 0, "and nothing is created for them");

    Expect(Discards(t.Translate(V4(1, Server, Wan, Icmp4(5, 0, IdSeq(7, 1), eight)), path), "§4.2"),
        "§4.2 silently drops the Redirect by name, and it is not one of §3.4's Query messages, so an identifier that happens to match one of ours cannot borrow a session");
    Expect(t.BindingCount == 0 && t.SessionCount == 0, "and the same for the IPv4 side's drop list");

    Expect(Discards(t.Translate(V6(44, ClientA, E6(Server),
        [.. FragHead(58, 0, true, 0x11), .. Icmp6(128, 0, IdSeq(7, 1), eight, ClientA, E6(Server))]), path),
        "Fragmented ICMP/ICMPv6 packets will not be translated"),
        "RFC 7915 §3: a fragmented ICMP message is not translated, and §3.4's 3-tuple needs the Identifier a later fragment does not carry");
}

// --- §3.4's error path, both directions ---------------------------------------------------------------------------------

{
    var t = NewNat();
    t.Translate(udpRequest, path);
    var quotedSeg = UdpSeg(Wan, Server, false, Nat64.PortFirst, 443, eight);
    var stored = U16(quotedSeg, 6);
    var quoted = V4(17, Wan, Server, quotedSeg, id: 0x7777);
    var e = t.Translate(V4(1, Server, Wan, Icmp4(3, 3, [0, 0, 0, 0], quoted)), path);
    var out6 = Read6(e);
    Expect(Forwarded(e),
        "§3.4: an ICMP error quoting a UDP packet gives a 5-tuple read from the embedded packet \"However, the role of source and destination is swapped\", and this one is that error");
    Expect(out6.Next == 58 && out6.Body[0] == 1 && out6.Body[1] == 4,
        "§4.2: \"Code 3 (Port Unreachable): Set the Code to 4 (Port unreachable)\" under a Type set to 1");
    var inner = Parse6(out6.Body[8..]);
    Expect(inner.Next == 17 && Is(inner.Src, ClientA) && Is(inner.Dst, E6(Server)),
        "§4.3's \"The translation of the inner IP header can be done by invoking the function that translated the outer IP headers\", with the quote's roles crossed relative to the message's");
    Expect(inner.Sport == 4000 && inner.Dport == 443,
        "§3.7: \"the source and destination ports are modified to the source and destination ports from the outgoing 5-tuple\" - here inside the quote, which is where the tuple lives");
    Expect(U16(inner.Body, 6) == Move(stored, Nat64.PortFirst, 4000),
        "and RFC 1624 §2's update moves the quoted checksum by that word alone, since the quote is a copy of a packet whose payload is not all here");
    Expect(ChecksumOk(Pseudo6(out6.Src, out6.Dst, 58, out6.Body.Length), out6.Body),
        "the message's own ICMPv6 checksum is recomputed over RFC 8200 §8.1's pseudo-header");
    Expect(t.SessionCount == 1 && t.BindingCount == 1,
        "§3.5: \"For the case of ICMP error messages, they do not affect in any way either the BIBs or the session tables\"");
}

{
    var t = NewNat();
    var o = t.Translate(udpRequest, path);
    var mapped = Read4(o).Sport;
    clock.Advance((int)Nat64.UdpDefault.TotalSeconds - 60);
    var e = t.Translate(V4(1, Server, Wan, Icmp4(3, 3, [0, 0, 0, 0],
        V4(17, Wan, Server, UdpSeg(Wan, Server, false, mapped, 443, eight)))), path);
    Expect(Forwarded(e), "the error still translates four minutes into a quiet flow");
    clock.Advance(70);
    t.Sweep();
    Expect(t.SessionCount == 0 && t.BindingCount == 0,
        "and RFC 5508's REQ-6: the error refreshed no timer, so the session reaches UDP_DEFAULT from the packet that made it, not from the error");
}

{
    var t = NewNat();
    t.Translate(udpRequest, path);
    var quoted = V4(17, Wan, Server, UdpSeg(Wan, Server, false, Nat64.PortFirst, 443, eight));

    var foreign = t.Translate(V4(1, Server, Wan, Icmp4(3, 3, [0, 0, 0, 0],
        V4(17, "198.51.100.77", Server, UdpSeg("198.51.100.77", Server, false, Nat64.PortFirst, 443, eight)))), path);
    Expect(Discards(foreign, "not this NAT64's own IPv4 address"),
        "§3.4's tuple is read from a packet this translator forwarded; a quote sourced from anywhere else is not, and the coincidence of one of our mapped ports in its source field cannot make it one");

    var errorInError = V4(1, Wan, Server, Icmp4(11, 0, [0, 0, 0, 0], none));
    Expect(Discards(t.Translate(V4(1, Server, Wan, Icmp4(3, 3, [0, 0, 0, 0], errorInError)), path),
        "containing an ICMP error message"),
        "§3.4: \"If the incoming IP packet contains a complete (un-fragmented) ICMP error message containing an ICMP error message, then the packet is silently discarded\"");

    var truncated = t.Translate(V4(1, Server, Wan, Icmp4(3, 3, [0, 0, 0, 0],
        V4(17, Wan, Server, none))), path);
    Expect(Discards(truncated, "stops before its transport ports"),
        "§3.4: \"If it is not possible to determine the incoming 5-tuple (perhaps because not enough of the embedded packet is reproduced inside the ICMP message), then the incoming IP packet MUST be silently discarded\"");

    var corrupt = V4(17, Wan, Server, UdpSeg(Wan, Server, false, Nat64.PortFirst, 443, eight));
    corrupt[10] ^= 0xFF;
    Expect(Discards(t.Translate(V4(1, Server, Wan, Icmp4(3, 3, [0, 0, 0, 0], corrupt)), path),
        "does not validate"),
        "RFC 5508's REQ-3a: \"if the IP checksum of the embedded packet fails to validate, the NAT SHOULD silently drop\" the error");

    Expect(Discards(t.Translate(V4(1, Server, Wan, Icmp4(3, 3, [0, 0, 0, 0],
        V4(132, Wan, Server, eight))), path), "none of the TCP, UDP or ICMP"),
        "§3.4 gives no tuple for a quoted protocol it does not name, so nothing can be looked up");

    var wrongPeer = t.Translate(V4(1, Stranger, Wan, Icmp4(3, 3, [0, 0, 0, 0], quoted)), path);
    Expect(Forwarded(wrongPeer) && Is(Read6(wrongPeer).Dst, ClientA),
        "§3.5: an ICMP error \"does not affect in any way either the BIBs or the session tables, so there is no processing resulting from these messages in this section. ICMP error message processing continues in Section 3.6\", and §3.6.1's search key is the quote's destination - so a message from a host the client never sent to is answered for the binding the quote names, which is the reading that keeps a real error from reaching the client when a middlebox rather than the peer sends it");
}

{
    // The client's own identifier is one this host's ICMP stack already holds, so the binding has to be made on a
    // different number - which is what makes the rewrite inside the quote below something the suite can see.
    var held7 = new HashSet<ushort> { 7 };
    var t = NewNat(localPorts: protocol => protocol == 1 ? held7 : new HashSet<ushort>());
    var ping = t.Translate(V6(58, ClientA, E6(Server), Icmp6(128, 0, IdSeq(7, 1), eight, ClientA, E6(Server))), path);
    var bound = U16(Read4(ping).Body, 4);
    Expect(bound != 7, "the query is put on the wire under the identifier the allocator could get, not the client's own");
    // The peer's router ran out of hops on the client's Echo Request and quotes it back. §3.4's third bullet makes
    // that a Query tuple read with the roles crossed, and §3.6.2 the search for the binding that owns the identifier
    // this table put on the wire.
    var quotedQuery = V4(1, Wan, Server, Icmp4(8, 0, IdSeq(bound, 1), eight));
    var e = t.Translate(V4(1, Server, Wan, Icmp4(11, 0, [0, 0, 0, 0], quotedQuery)), path);
    Expect(Forwarded(e),
        "§3.4: \"If the incoming IP packet contains a complete (un-fragmented) ICMP error message containing an ICMP Query message, then the incoming 3-tuple is computed by extracting the appropriate fields from the IP packet embedded inside\", and this one is that case");
    var out6 = Read6(e);
    Expect(out6.Body[0] == 3 && out6.Body[1] == 0, "§4.2: \"Time Exceeded (Type 11): Set the Type to 3 ... The Code is unchanged\"");
    Expect(Is(out6.Src, E6(Server)) && Is(out6.Dst, ClientA), "and the crossed pair the quote gives is what §3.6.2 sends the message to");
    var inner = Parse6(out6.Body[8..]);
    Expect(U16(inner.Body, 4) == 7,
        "§3.7's third bullet reaches into the quote: \"the ICMP Identifier is set to the ICMP Identifier from the outgoing 3-tuple\", which is the client's own");
    Expect(t.SessionCount == 1 && t.BindingCount == 1, "and the tables are untouched, as §3.5 says of every error");

    Expect(Discards(t.Translate(V4(1, Server, Wan, Icmp4(11, 0, [0, 0, 0, 0],
        V4(1, Wan, Server, Icmp4(8, 0, [0, 0, 0, 0], none), id: 0x22))), path), "no binding owns identifier"),
        "an error quoting a query whose identifier none of our bindings owns is the one case §3.6.2 cannot answer, and it is the only thing about this packet that says so - the type, the code and the quoted addresses all read as a message to translate");
}

{
    var t = NewNat();
    var syn = t.Translate(V6(6, ClientA, E6(Server), TcpSeg(ClientA, E6(Server), true, 4000, 443, 0x02, none)), path);
    var mapped = Read4(syn).Sport;
    // The client answers our forwarded SYN-ACK with a port unreachable because its side of the connection went
    // away. The quote is the packet the client received, so §3.4's swap makes the tuple the one travelling this
    // way, and §3.6.1's IPv6-to-IPv4 half asks the BIB for (S',s) directly.
    var quotedSeg = TcpSeg(E6(Server), ClientA, true, 443, 4000, 0x10, none);
    var stored = U16(quotedSeg, 16);
    var quoted = V6(6, E6(Server), ClientA, quotedSeg);
    var e = t.Translate(V6(58, ClientA, E6(Server), Icmp6(1, 4, [0, 0, 0, 0], quoted, ClientA, E6(Server))), path);
    Expect(Forwarded(e),
        "§3.4's error bullets read \"the incoming IP packet\" in either direction, and §3.5 sends an ICMPv6 error to §3.6 with the same step the IPv4 leg takes");
    var out4 = Read4(e);
    Expect(out4.Proto == 1 && Is(out4.Src, Wan) && Is(out4.Dst, Server),
        "§3.6.1: \"When translating from IPv6 ICMP to IPv4 ICMP, the protocol number in the protocol field of the IP header is set to 1\", the source is the binding's T and the destination D' read algorithmically");
    Expect(out4.Body[0] == 3 && out4.Body[1] == 3, "§5.2's Destination Unreachable code list maps 4 (Port unreachable) to 3");
    var inner = Parse4(out4.Body[8..]);
    Expect(inner.Proto == 6 && Is(inner.Src, Server) && Is(inner.Dst, Wan) && inner.Sport == 443 && inner.Dport == mapped,
        "§4.3's inner-header rule gives the quote the same function, so it comes back as the packet this translator really sent");
    Expect(U16(inner.Body, 16) == Move(stored, 4000, mapped), "and RFC 1624 §2's update moves the quoted checksum with the port");
    Expect(ChecksumOk(out4.Body), "RFC 792 §1's checksum, which needs no pseudo-header on the IPv4 side");
    Expect(t.SessionCount == 1 && t.BindingCount == 1, "§3.5: no table is touched by an error");
}

{
    var t = NewNat();
    var nested = t.Translate(V6(58, ClientA, E6(Server), Icmp6(3, 0, [0, 0, 0, 0],
        V6(58, E6(Server2), ClientA, Icmp6(3, 0, [0, 0, 0, 0], none, E6(Server2), ClientA)), ClientA, E6(Server))), path);
    Expect(Discards(nested, "containing an ICMP error message"),
        "RFC 4443 §2.4's note is what this reads: \"ICMPv6 error messages are those with a Type value of 1 through 127\", so a Time Exceeded (3) inside an error is §3.4's error-in-error case, not a Query with an MTU in its identifier field");
    Expect(t.BindingCount == 0 && t.SessionCount == 0, "and it is discarded before any identifier is spent");

    var shortQuote = t.Translate(V6(58, ClientA, E6(Server),
        Icmp6(1, 4, [0, 0, 0, 0], V6(6, E6(Server), ClientA, none), ClientA, E6(Server))), path);
    Expect(Discards(shortQuote, "stops before its transport ports"),
        "§3.4: the MUST when the quote stops short of the ports the tuple needs");

    Expect(Discards(t.Translate(V6(58, ClientA, E6(Server),
        Icmp6(2, 0, [0, 0, 0x05, 0x78], V6(6, E6(Server), ClientA, none), ClientA, E6(Server))), path),
        "stops before its transport ports"),
        "and a Packet Too Big (type 2) is the same case one type over - RFC 4443 §2.4's note counts it among the errors, and its 40-octet quote holds no transport ports");
}

// --- §3.4's fragment conditions -------------------------------------------------------------------------------------------

{
    var t = NewNat();
    var first = V6(44, ClientA, E6(Server),
        [.. FragHead(17, 0, true, 0x1122), .. UdpSeg(ClientA, E6(Server), true, 4000, 443, eight)]);
    var o = t.Translate(first, path);
    Expect(Forwarded(o) && t.FragmentRecordCount == 1,
        "§3.4: \"a NAT64 MAY translate the fragments as they arrive, by storing information that allows it to compute the 5-tuple for fragments other than the first\" - this table stores the binding the first one settled");
    var second = t.Translate(V6(44, ClientA, E6(Server),
        [.. FragHead(17, 1, false, 0x1122), .. new byte[] { 9, 10, 11, 12, 13, 14, 15, 16 }]), path);
    var out4 = Read4(second);
    Expect(Forwarded(second), "and the fragment that arrives after it has the ports read from that record");
    Expect(out4.Offset == 1 && !out4.More && out4.Id == 0x1122,
        "§5.1.1: the IPv4 More Fragments flag \"is copied from the M flag in the IPv6 Fragment Header\", the offset with it, and the Identification from the Fragment Header's own");
    Expect(t.FragmentReuses == 1 && t.FragmentRecordCount == 1, "the reuse is counted, and the record is kept for the fragment after that");

    var other = t.Translate(V6(44, ClientA, E6(Server),
        [.. FragHead(17, 1, false, 0x9999), .. eight]), path);
    Expect(Discards(other, "no first fragment of this datagram came through"),
        "§3.4's MUST handle fragments \"arriving out of order\" is satisfied by the record the first one leaves; a stray fragment with no first has nothing to be read from");
    Expect(t.FragmentRefused == 1, "and the refusal is counted apart from the missing binding");

    clock.Advance((int)Nat64.FragmentWindow.TotalSeconds + 1);
    t.Sweep();
    Expect(t.FragmentRecordCount == 0,
        $"§3.4: \"the NAT64 MUST allow the fragments to arrive over a time interval ... and the default value MUST be of at least FRAGMENT_MIN\" (2 seconds) - this table's interval is {Nat64.FragmentWindow.TotalSeconds:0} seconds and the record ages out of it");
    Expect(Discards(t.Translate(V6(44, ClientA, E6(Server),
        [.. FragHead(17, 1, false, 0x1122), .. eight]), path), "no first fragment"),
        "and after the window the later fragment is the same stray case");
}

{
    var t = NewNat();
    t.Translate(V6(44, ClientA, E6(Server),
        [.. FragHead(17, 0, true, 0x1122), .. UdpSeg(ClientA, E6(Server), true, 4000, 443, eight)]), path);
    var mid = V6(44, ClientA, E6(Server), [.. FragHead(17, 1, true, 0x1122), .. eight]);
    Expect(Forwarded(t.Translate(mid, path)), "a middle fragment forwards, and its arrival restarts the interval");
    clock.Advance((int)Nat64.FragmentWindow.TotalSeconds - 1);
    Expect(Forwarded(t.Translate(mid, path)) && t.FragmentRecordCount == 1,
        "so the next one inside that window still has its record, even though the first fragment is over two minutes old");
    clock.Advance((int)Nat64.FragmentWindow.TotalSeconds - 1);
    t.Sweep();
    Expect(t.FragmentRecordCount == 1, "and the sweep reaps only records whose own interval has closed");
}

{
    var t = NewNat();
    var o = t.Translate(udpRequest, path);
    var mapped = Read4(o).Sport;
    Expect(Discards(t.Translate(V4(17, Server, Wan, UdpSeg(Server, Wan, false, 443, mapped, eight, checksum: 0),
        id: 0x5566, flags: 0x2000), path), "first fragment of a fragmented UDP packet carries no checksum"),
        "RFC 7915 §4.5: \"when a stateless translator receives the first fragment of a fragmented UDP IPv4 packet and the checksum field is zero, the translator SHOULD drop the packet\" - which is also §3.4's no-resources branch of the zero-checksum rule, and a whole datagram of the same flow does get its checksum computed by the recompute in §4.5's other branch");
    Expect(t.FragmentRecordCount == 0, "and a refused first fragment records nothing, so its later ones have nothing to be read from");
    Expect(Discards(t.Translate(V4(17, Server, Wan, eight, id: 0x5566, flags: 8), path), "no first fragment"),
        "which is what the second fragment of that datagram gets");

    var whole = t.Translate(V4(17, Server, Wan, UdpSeg(Server, Wan, false, 443, mapped, eight, checksum: 0)), path);
    var out6 = Read6(whole);
    Expect(Forwarded(whole) && U16(out6.Body, 6) != 0 &&
           ChecksumOk(Pseudo6(out6.Src, out6.Dst, 17, out6.Body.Length), out6.Body),
        "§3.4: \"For incoming IPv4 packets carrying UDP packets with a zero checksum, if the NAT64 has enough resources, the NAT64 MUST reassemble the packets and MUST calculate the checksum\" - unfragmented, the whole datagram is here, so RFC 7915 §4.5's recompute is that MUST and the client never sees a zero-checksum UDP packet");
}

{
    var t = NewNat();
    Expect(Discards(t.Translate(V4(17, Server, Wan, [0x01, 0x02], id: 0x5566, flags: 0x2000), path),
        "completely contained within the fragment that contains fragment offset equal to zero"),
        "§3.4's third fragment bullet, taken: a first fragment that stops inside the transport header is not translated");
    Expect(Discards(t.Translate(V6(44, ClientA, E6(Server), [.. FragHead(17, 0, true, 0x1122), 0x01, 0x02]), path),
        "completely contained within the fragment that contains fragment offset equal to zero"),
        "and the same on the IPv6 side, where the fragment header stands where the transport header would");
}

{
    var t = NewNat();
    var o = t.Translate(udpRequest, path);
    var mapped = Read4(o).Sport;
    var replyFirst = V4(17, Server, Wan, UdpSeg(Server, Wan, false, 443, mapped, eight), id: 0x3344, flags: 0x2000);
    Expect(Forwarded(t.Translate(replyFirst, path)), "the answer's first fragment makes its record on this side too");
    var replySecond = V4(17, Server, Wan, eight, id: 0x3344, flags: 1);
    var out6 = Read6(t.Translate(replySecond, path));
    Expect(out6.Fragmented && out6.FragNext == 17 && out6.Offset == 1 && !out6.More && out6.FragId == 0x3344,
        "§4.1's Fragment Header rows: the offset and the M flag copied from the IPv4 header, the low-order 16 bits of the Identification, and the protocol left to the Fragment Header's own first octet");
    var framed = V4(17, Server, Wan, eight, id: 0x3344, flags: 1);
    Expect(t.OwnsDatagram(framed) && !t.OwnsDatagram(V4(17, Server, Wan, eight, id: 0x7777, flags: 1)),
        "and the reply dispatch can see that a fragment other than the first is this table's, which no port would tell it");
}

{
    var t = NewNat();
    for (var i = 0; i < Nat64.FragmentCeiling; i++)
    {
        var port = (ushort)(1024 + i);
        t.Translate(V6(44, ClientA, E6(Server),
            [.. FragHead(17, 0, true, (uint)(i + 1)), .. UdpSeg(ClientA, E6(Server), true, port, 443, eight)]), path);
    }
    Expect(t.FragmentRecordCount == Nat64.FragmentCeiling,
        $"§3.4's first fragment bullet: \"The NAT64 MUST limit the amount of resources devoted to the storage of fragmented packets in order to protect from DoS attacks\" - the ceiling is {Nat64.FragmentCeiling} records");
    var before = t.FragmentRefused;
    var refused = t.Translate(V6(44, ClientA, E6(Server2),
        [.. FragHead(17, 0, true, 0x8000), .. UdpSeg(ClientA, E6(Server2), true, 60000, 443, eight)]), path);
    Expect(Forwarded(refused) && t.FragmentRefused == before + 1 && t.FragmentRecordCount == Nat64.FragmentCeiling,
        "past it a new datagram is still translated - the first fragment carries its own tuple - but nothing is stored for the fragments behind it");
    Expect(Discards(t.Translate(V6(44, ClientA, E6(Server2),
        [.. FragHead(17, 1, false, 0x8000), .. eight]), path), "no first fragment"),
        "and they are refused, which is the difference the ceiling has to be able to show");
}

// --- §3.8's hairpinning ----------------------------------------------------------------------------------------------------

{
    var t = NewNat();
    // B's own client port is inside the range this table can answer on, so §3.5.1.1's first preference gives the
    // binding that number and the port B addressed itself to is one its reverse key already holds.
    var bToUs = V6(17, ClientB, E6(Wan), UdpSeg(ClientB, E6(Wan), true, 50000, 50000, eight));
    var looped = t.Translate(bToUs, path);
    var back = Read6(looped);
    Expect(Forwarded(looped) && Is(back.Src, E6(Wan)) && Is(back.Dst, ClientB),
        "§3.8: a datagram whose translated destination is one of this translator's own IPv4 addresses \"is treated as if it was received on the outgoing interface\", and B's own binding owns the port it addressed");
    Expect(U16(back.Body, 0) == 50000,
        "§3.6's NOTE is what keeps the source right in that second pass: the binding translates an IPv6 source to an IPv4 one and an IPv4 destination to an IPv6 one, \"the latter cases are handled by applying the algorithmic transformation\", so a hairpin's source is this address in the other family rather than the client that owns the binding");

    var aToB = V6(17, ClientA, E6(Wan), UdpSeg(ClientA, E6(Wan), true, 4000, 50000, eight));
    var hair = t.Translate(aToB, path);
    var toB = Read6(hair);
    Expect(Forwarded(hair) && Is(toB.Dst, ClientB) && Is(toB.Src, E6(Wan)) && toB.Sport == Nat64.PortFirst && toB.Dport == 50000,
        "and A reaches B through the NAT: the source stays the address B itself named, the destination comes from B's binding, and the port A sent from is the one B sees");
    Expect(t.Hairpins == 2, "§3.8 counted both U-turns");
    Expect(t.Translated64 == 2 && t.Translated46 == 2, "each of which is the two translations §3.8's re-entry at step 2 is made of");

    var ping = t.Translate(V6(58, ClientA, E6(Wan), Icmp6(128, 0, IdSeq(7, 1), eight, ClientA, E6(Wan))), path);
    Expect(Forwarded(ping) && Read4(ping).Proto == 1 && t.Hairpins == 2,
        "§2: \"Hairpin packets can be either TCP or UDP\", so an ICMP query aimed at this address goes out on the wire as any other packet would instead of being re-entered");
}

// --- a lease renewal that moves the address the whole table binds to -------------------------------------------------------

{
    var t = NewNat();
    var o = t.Translate(udpRequest, path);
    Expect(Read4(o).Sport == Nat64.PortFirst && Is(Read4(o).Src, Wan), "the flow is made under this lease's address");
    t.SetWanAddress(IPAddress.Parse(Wan2));
    var second = t.Translate(V6(17, ClientA, E6(Server2), UdpSeg(ClientA, E6(Server2), true, 4000, 443, eight)), path);
    Expect(Forwarded(second) && Is(Read4(second).Src, Wan2) && Read4(second).Sport == Nat64.PortFirst,
        "and after the renewal the same binding writes the new source: nothing keys on the address, which is §5.2's Endpoint-Independent Mapping read the other way");
    Expect(t.OwnsDatagram(V4(17, Server, Wan2, UdpSeg(Server, Wan2, false, 443, Nat64.PortFirst, eight))),
        "the reply leg now arrives on the new address");
    Expect(!t.OwnsDatagram(V4(17, Server, Wan, UdpSeg(Server, Wan, false, 443, Nat64.PortFirst, eight))),
        "and a packet to the address the lease no longer holds stays with whoever still answers it");
    Expect(Forwarded(t.Translate(V4(17, Server, Wan2, UdpSeg(Server, Wan2, false, 443, Nat64.PortFirst, eight)), path)),
        "so the old flow's answer still finds its session under the new address");
}

// --- every discard cites itself --------------------------------------------------------------------------------------------

{
    var t = NewNat();
    t.Translate(udpRequest, path);
    var cases = new (string What, byte[] Packet)[]
    {
        ("a UDP reply with no binding", V4(17, Server, Wan, UdpSeg(Server, Wan, false, 443, 60001, eight))),
        ("a UDP reply from a peer that was never sent to", V4(17, Stranger, Wan, UdpSeg(Stranger, Wan, false, 443, Nat64.PortFirst, eight))),
        ("a stray fragment", V4(17, Server, Wan, eight, id: 0x7777, flags: 5)),
        ("an ICMPv4 query with no binding", V4(1, Server, Wan, Icmp4(0, 0, IdSeq(4000, 1), eight))),
        ("an ICMPv4 error quoting a foreign packet", V4(1, Server, Wan, Icmp4(3, 3, [0, 0, 0, 0], V4(6, "198.51.100.77", Server, TcpSeg("198.51.100.77", Server, false, Nat64.PortFirst, 443, 0x10, none))))),
        ("a protocol this table does not read", V4(47, Server, Wan, eight)),
        ("a v6 packet out of the prefix in its source", V6(17, E6(Server), E6(Server2), UdpSeg(E6(Server), E6(Server2), true, 4000, 443, eight))),
    };
    foreach (var (what, packet) in cases)
    {
        var outcome = t.Translate(packet, path);
        Expect(outcome.Action != Nat64Action.Translate || outcome.Packet is not null,
            $"a {what} either forwards a packet or explains why it did not");
        if (outcome.Action == Nat64Action.Discard)
            Expect(!string.IsNullOrWhiteSpace(outcome.Reason),
                $"and a {what} carries the clause it was discarded under, not a null");
    }
}

foreach (var failure in failures) Console.WriteLine($"FAIL {failure}");
if (failures.Count > 0)
{
    Console.WriteLine($"[nat64check] FAIL - {failures.Count} of {failures.Count + notes.Count} RFC 6146 assertions");
    return 1;
}

Console.WriteLine($"[nat64check] PASS - {notes.Count} RFC 6146 stateful-NAT64 assertions");
return 0;

internal sealed class Clock
{
    public DateTime Now = new(2026, 11, 2, 0, 0, 0, DateTimeKind.Utc);
    public void Advance(int seconds) => Now = Now.AddSeconds(seconds);
}

internal sealed record P4(byte[] Src, byte[] Dst, byte Proto, int Transport, ushort Id, bool More, int Offset,
    bool HeaderOk, byte Ttl, byte[] Body)
{
    public ushort Sport => (ushort)(Body[0] << 8 | Body[1]);
    public ushort Dport => (ushort)(Body[2] << 8 | Body[3]);
}

internal sealed record P6(byte[] Src, byte[] Dst, byte Next, int Transport, bool Fragmented, byte FragNext,
    int Offset, bool More, uint FragId, byte HopLimit, byte[] Body)
{
    public ushort Sport => (ushort)(Body[0] << 8 | Body[1]);
    public ushort Dport => (ushort)(Body[2] << 8 | Body[3]);
}
