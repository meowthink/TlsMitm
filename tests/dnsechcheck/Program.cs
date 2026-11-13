using System.Buffers.Binary;
using System.Net;
using System.Text;
using Router;

// Offline judgement for the packet-level ECH strip: DnsEch.TryNeutralize has to find the DNS message inside
// a v4/v6 UDP/TCP answer (source port 53), rewrite the HTTPS/SVCB "ech" SvcParam in place, and leave alone
// anything it cannot read whole - a query, a fragment, a truncated datagram. The message-level rewrite is
// servcheck's subject; this is the framing around it. No driver, no socket; the checksums are not verified
// here (the driver recalculates them), only the finding and the in-place rewrite.
var failures = new List<string>();
void Expect(bool ok, string what)
{
    if (!ok) failures.Add(what);
    Console.WriteLine($"{(ok ? "ok  " : "FAIL")} {what}");
}

// --- builders ---------------------------------------------------------------------------------------
static byte[] Short(ushort v) { var b = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(b, v); return b; }
static byte[] Name(string name)
{
    var b = new List<byte>();
    if (name != ".")
        foreach (var label in name.Split('.'))
        {
            if (label.Length == 0) continue;
            var raw = Encoding.ASCII.GetBytes(label);
            b.Add((byte)raw.Length);
            b.AddRange(raw);
        }
    b.Add(0);
    return b.ToArray();
}

static byte[] HttpsRdata(ushort priority, string target, params (ushort Key, byte[] Value)[] parameters)
{
    var rdata = new List<byte>(Short(priority));
    rdata.AddRange(Name(target));
    foreach (var (key, value) in parameters)
    {
        rdata.AddRange(Short(key));
        rdata.AddRange(Short((ushort)value.Length));
        rdata.AddRange(value);
    }
    return rdata.ToArray();
}

static byte[] DnsMsg(string name, ushort type, byte[] rdata)
{
    var question = new List<byte>();
    question.AddRange(Name(name));
    question.AddRange(Short(type));
    question.AddRange(Short(DnsFormat.ClassInternet));
    var answer = new List<byte>();
    answer.AddRange(Name(name));
    answer.AddRange(Short(type));
    answer.AddRange(Short(DnsFormat.ClassInternet));
    answer.AddRange(new byte[] { 0, 0, 0, 60 });          // TTL 60
    answer.AddRange(Short((ushort)rdata.Length));
    answer.AddRange(rdata);
    var msg = new byte[12 + question.Count + answer.Count];
    BinaryPrimitives.WriteUInt16BigEndian(msg.AsSpan(0), 0x1234);
    BinaryPrimitives.WriteUInt16BigEndian(msg.AsSpan(2), 0x8000);   // response, NOERROR
    BinaryPrimitives.WriteUInt16BigEndian(msg.AsSpan(4), 1);        // QDCOUNT
    BinaryPrimitives.WriteUInt16BigEndian(msg.AsSpan(6), 1);        // ANCOUNT
    question.CopyTo(msg, 12);
    answer.CopyTo(msg, 12 + question.Count);
    return msg;
}

static byte[] Udp(byte[] dns, ushort srcPort, ushort dstPort)
{
    var p = new byte[8 + dns.Length];
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(0), srcPort);
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), dstPort);
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(4), (ushort)(8 + dns.Length));
    dns.CopyTo(p, 8);
    return p;
}

static byte[] Tcp(byte[] dns, ushort srcPort, ushort dstPort)
{
    var p = new byte[20 + 2 + dns.Length];
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(0), srcPort);
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), dstPort);
    p[12] = 0x50;                                          // data offset 5
    p[13] = 0x18;                                          // PSH+ACK
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(20), (ushort)dns.Length);   // RFC 1035 §4.2.2 length
    dns.CopyTo(p, 22);
    return p;
}

static byte[] V4(byte[] transport, byte protocol, ushort fragOff = 0)
{
    var p = new byte[20 + transport.Length];
    p[0] = 0x45;
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), (ushort)p.Length);
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(6), fragOff);
    p[8] = 64;
    p[9] = protocol;
    IPAddress.Parse("198.51.100.7").GetAddressBytes().CopyTo(p, 12);
    IPAddress.Parse("192.0.2.10").GetAddressBytes().CopyTo(p, 16);
    transport.CopyTo(p, 20);
    return p;
}

static byte[] V6(byte[] transport, byte nextHeader)
{
    var p = new byte[40 + transport.Length];
    p[0] = 0x60;
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(4), (ushort)transport.Length);
    p[6] = nextHeader;
    p[7] = 64;
    IPAddress.Parse("2001:db8::99").GetAddressBytes().CopyTo(p, 8);
    IPAddress.Parse("2001:db8::10").GetAddressBytes().CopyTo(p, 24);
    transport.CopyTo(p, 40);
    return p;
}

var echConfig = Encoding.ASCII.GetBytes("AEX+DQBBAAA=");
byte[] EchRdata() => HttpsRdata(1, ".", (1, Encoding.ASCII.GetBytes("h2")), (DnsFormat.SvcParamEch, echConfig));
byte[] EchMsg() => DnsMsg("ech.example.com", DnsFormat.TypeHttps, EchRdata());
const ushort Svc = DnsPorts.ServerPort;

// --- the four shapes: v4/v6 × UDP/TCP ----------------------------------------------------------------
foreach (var (label, packet) in new (string, byte[])[]
{
    ("v4/UDP", V4(Udp(EchMsg(), Svc, 50000), 17)),
    ("v4/TCP", V4(Tcp(EchMsg(), Svc, 50000), 6)),
    ("v6/UDP", V6(Udp(EchMsg(), Svc, 50000), 17)),
    ("v6/TCP", V6(Tcp(EchMsg(), Svc, 50000), 6)),
})
{
    var before = packet.ToArray();
    var n = DnsEch.TryNeutralize(packet);
    Expect(n == 1, $"{label}: the one ech parameter is rewritten, got {n}");
    Expect(packet.Length == before.Length, $"{label}: the packet keeps its length");
    Expect(DnsEch.TryNeutralize(packet) == 0, $"{label}: a second pass finds nothing left");
}

// --- a query (source port not 53) is left alone ------------------------------------------------------
var query = V4(Udp(EchMsg(), 50000, Svc), 17);
var queryBefore = query.ToArray();
Expect(DnsEch.TryNeutralize(query) == 0 && query.SequenceEqual(queryBefore),
    "a packet whose source port is not the resolver's is left exactly as it arrived");

// --- a fragment is not rewritten ---------------------------------------------------------------------
var frag = V4(Udp(EchMsg(), Svc, 50000), 17, fragOff: 0x0001);
Expect(DnsEch.TryNeutralize(frag) == 0, "a non-first fragment is left alone");

// --- no ech parameter: unchanged ---------------------------------------------------------------------
var plain = V4(Udp(DnsMsg("plain.example.com", DnsFormat.TypeHttps,
    HttpsRdata(1, ".", (1, Encoding.ASCII.GetBytes("h2")))), Svc, 50000), 17);
var plainBefore = plain.ToArray();
Expect(DnsEch.TryNeutralize(plain) == 0 && plain.SequenceEqual(plainBefore),
    "an HTTPS record with no ech parameter is left exactly as it arrived");

// --- two ech parameters in one record ----------------------------------------------------------------
var two = V4(Udp(DnsMsg("two.example.com", DnsFormat.TypeHttps,
    HttpsRdata(1, ".", (DnsFormat.SvcParamEch, echConfig), (DnsFormat.SvcParamEch, echConfig))), Svc, 50000), 17);
Expect(DnsEch.TryNeutralize(two) == 2, "both ech parameters of one record are rewritten");

// --- truncated and malformed: refuse, never crash ----------------------------------------------------
static bool Survives(Action act) { try { act(); return true; } catch { return false; } }
Expect(DnsEch.TryNeutralize(new byte[1]) == 0, "a one-octet packet is left alone");
Expect(DnsEch.TryNeutralize(new byte[19]) == 0, "a packet shorter than an IPv4 header is left alone");
var full = V4(Udp(EchMsg(), Svc, 50000), 17);
Expect(Survives(() => DnsEch.TryNeutralize(full.AsSpan(0, full.Length - 5).ToArray())),
    "a datagram cut inside the DNS message does not crash");
Expect(Survives(() => DnsEch.TryNeutralize(V6(Udp(EchMsg(), Svc, 50000), 17).AsSpan(0, 45).ToArray())),
    "a v6 datagram cut inside the transport does not crash");
Expect(DnsEch.TryNeutralize(V4(Udp(EchMsg(), Svc, 50000), 47)) == 0, "a non-TCP/UDP protocol is left alone");

if (failures.Count > 0)
{
    Console.WriteLine($"[dnsechcheck] FAIL ({failures.Count})");
    return 1;
}
Console.WriteLine("[dnsechcheck] PASS - ECH strip across v4/v6 UDP/TCP, query/fragment/no-ech left alone, multi-param, truncation");
return 0;
