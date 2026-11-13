using System.Buffers.Binary;
using System.Net;
using Router;

// Offline judgement for the router's DNS64 (RFC 6147): the §5.1 verdict on an upstream AAAA answer, the
// §5.1.4 exclusion of IPv4-mapped addresses, the §5.4 synthesis of AAAA from A, the §5.1.7 TTL ceiling,
// and the §5.3.1 PTR redirect. No socket, no resolver, no clock - crafted DNS messages in, decisions and
// bytes out. The expected addresses are written out by hand so the assertions do not lean on the product's
// own Pref64 arithmetic to judge it.
var failures = new List<string>();

void Expect(bool ok, string what)
{
    if (!ok) failures.Add(what);
    Console.WriteLine($"{(ok ? "ok  " : "FAIL")} {what}");
}

// --- message builders -------------------------------------------------------------------------------
static byte[] Be16(ushort v) { var b = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(b, v); return b; }
static byte[] Be32(uint v) { var b = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(b, v); return b; }

static byte[] Name(string name)
{
    var b = new List<byte>();
    foreach (var label in name.Split('.'))
    {
        var raw = System.Text.Encoding.ASCII.GetBytes(label);
        b.Add((byte)raw.Length);
        b.AddRange(raw);
    }
    b.Add(0);
    return b.ToArray();
}

static byte[] V4(string addr) => IPAddress.Parse(addr).GetAddressBytes();
static byte[] V6(string addr) => IPAddress.Parse(addr).GetAddressBytes();
// ::ffff:a.b.c.d - the IPv4-mapped shape §5.1.4 excludes by default.
static byte[] Mapped(string v4)
{
    var b = new byte[16];
    b[10] = 0xff; b[11] = 0xff;
    V4(v4).CopyTo(b, 12);
    return b;
}

static byte[] Msg(ushort id, ushort flags, string qname, ushort qtype, params Rec[] recs)
{
    var question = new List<byte>();
    question.AddRange(Name(qname));
    question.AddRange(Be16(qtype));
    question.AddRange(Be16(DnsFormat.ClassInternet));
    var body = new List<byte>();
    var counts = new ushort[3];
    foreach (var r in recs)
    {
        body.AddRange(Name(r.Name));
        body.AddRange(Be16(r.Type));
        body.AddRange(Be16(DnsFormat.ClassInternet));
        body.AddRange(Be32(r.Ttl));
        body.AddRange(Be16((ushort)r.RData.Length));
        body.AddRange(r.RData);
        counts[r.Section]++;
    }
    var msg = new byte[DnsFormat.HeaderLength + question.Count + body.Count];
    BinaryPrimitives.WriteUInt16BigEndian(msg.AsSpan(0), id);
    BinaryPrimitives.WriteUInt16BigEndian(msg.AsSpan(2), flags);
    BinaryPrimitives.WriteUInt16BigEndian(msg.AsSpan(4), 1);
    for (var s = 0; s < 3; s++) BinaryPrimitives.WriteUInt16BigEndian(msg.AsSpan(6 + s * 2), counts[s]);
    question.CopyTo(msg, DnsFormat.HeaderLength);
    body.CopyTo(msg, DnsFormat.HeaderLength + question.Count);
    return msg;
}

const ushort NoError = 0x8000, NxDomain = 0x8003, ServFail = 0x8002;
Rec A(string name, uint ttl, string addr) => new(0, name, DnsFormat.TypeA, ttl, V4(addr));
Rec Aaaa(string name, uint ttl, byte[] addr) => new(0, name, DnsFormat.TypeAaaa, ttl, addr);

static List<(ushort Type, uint Ttl, byte[] RData)> Section(byte[] msg, int section)
{
    var list = new List<(ushort, uint, byte[])>();
    if (!DnsFormat.TryReadSections(msg, out _, out var recs)) return list;
    foreach (var (offset, sec) in recs)
    {
        if ((int)sec != section) continue;
        if (!DnsFormat.TryReadName(msg, offset, out _, out var at)) return list;
        var type = BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(at));
        var ttl = BinaryPrimitives.ReadUInt32BigEndian(msg.AsSpan(at + 4));
        var rdlen = BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(at + 8));
        list.Add((type, ttl, msg.AsSpan(at + 10, rdlen).ToArray()));
    }
    return list;
}

// RFC 3596 §2.5: the reverse name, low-order nibble first.
static string Ip6Arpa(IPAddress addr)
{
    var b = addr.GetAddressBytes();
    var nibbles = new List<string>();
    for (var i = b.Length - 1; i >= 0; i--)
    {
        nibbles.Add((b[i] & 0x0f).ToString("x"));
        nibbles.Add((b[i] >> 4).ToString("x"));
    }
    return string.Join('.', nibbles) + ".ip6.arpa";
}

var pref = Pref64Config.WellKnown;

// --- §5.1 classification ----------------------------------------------------------------------------
Expect(Dns64.Classify(Msg(1, NoError, "x.example", DnsFormat.TypeAaaa)) == Dns64.Verdict.Empty,
    "an answer with no records is Empty");
Expect(Dns64.Classify(Msg(1, NoError, "x.example", DnsFormat.TypeAaaa,
    Aaaa("x.example", 60, V6("2001:db8::1")))) == Dns64.Verdict.Usable,
    "a real AAAA address is Usable");
Expect(Dns64.Classify(Msg(1, NoError, "x.example", DnsFormat.TypeAaaa,
    Aaaa("x.example", 60, Mapped("192.0.2.1")))) == Dns64.Verdict.ExcludedOnly,
    "an IPv4-mapped AAAA alone is ExcludedOnly");
Expect(Dns64.Classify(Msg(1, NoError, "x.example", DnsFormat.TypeAaaa,
    Aaaa("x.example", 60, V6("2001:db8::1")), Aaaa("x.example", 60, Mapped("192.0.2.1")))) == Dns64.Verdict.Mixed,
    "a usable and a mapped AAAA together are Mixed");
Expect(Dns64.Classify(Msg(1, NoError, "x.example", DnsFormat.TypeAaaa,
    A("x.example", 60, "192.0.2.1"))) == Dns64.Verdict.Empty,
    "an A record is not AAAA data, so the answer classifies Empty");
Expect(Dns64.Classify(Msg(1, NxDomain, "x.example", DnsFormat.TypeAaaa)) == Dns64.Verdict.NameError,
    "RCODE 3 is NameError");
Expect(Dns64.Classify(Msg(1, ServFail, "x.example", DnsFormat.TypeAaaa)) == Dns64.Verdict.Failed,
    "RCODE 2 is Failed");
Expect(Dns64.Classify(new byte[4]) == Dns64.Verdict.Failed,
    "a message shorter than the header is Failed");

// --- §5.1.4 exclusion --------------------------------------------------------------------------------
var mixed = Msg(1, NoError, "x.example", DnsFormat.TypeAaaa,
    Aaaa("x.example", 60, V6("2001:db8::1")), Aaaa("x.example", 60, Mapped("192.0.2.1")),
    A("x.example", 60, "192.0.2.9"));
var stripped = Dns64.WithoutExcluded(mixed);
Expect(stripped != null, "WithoutExcluded reads a mixed answer");
var kept = Section(stripped!, 0);
Expect(kept.Count == 2, $"the mapped AAAA is dropped and the usable AAAA plus the A stay, got {kept.Count}");
Expect(kept.Any(r => r.Type == DnsFormat.TypeAaaa && r.RData.SequenceEqual(V6("2001:db8::1"))),
    "the usable AAAA survives the exclusion");
Expect(!kept.Any(r => r.Type == DnsFormat.TypeAaaa && r.RData.StartsWith(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff })),
    "no IPv4-mapped AAAA survives");
Expect(BinaryPrimitives.ReadUInt16BigEndian(stripped!.AsSpan(6)) == 2, "the answer count is rewritten to match");

// --- §5.4 synthesis ----------------------------------------------------------------------------------
var request = Msg(0x1234, 0x0100, "www.example.com", DnsFormat.TypeAaaa);
DnsFormat.TryReadSections(request, out var questionEnd, out _);
var emptyAaaa = Msg(0, NoError, "www.example.com", DnsFormat.TypeAaaa);
var aResponse = Msg(0, NoError, "www.example.com", DnsFormat.TypeA, A("www.example.com", 300, "192.0.2.1"));

var synth = Dns64.Synthesize(request, questionEnd, emptyAaaa, aResponse, pref);
Expect(synth != null, "an A answer with a usable record synthesizes");
var answers = Section(synth!, 0);
Expect(answers.Count == 1 && answers[0].Type == DnsFormat.TypeAaaa, "the synthesis is one AAAA record");
Expect(answers[0].RData.Length == 16, "the synthetic AAAA is 16 octets");
Expect(answers[0].RData.AsSpan(12).SequenceEqual(V4("192.0.2.1")),
    "the well-known prefix carries the A address in its low 32 bits");
Expect(answers[0].RData.AsSpan(0, 4).SequenceEqual(new byte[] { 0x00, 0x64, 0xff, 0x9b }),
    "the synthetic address starts with 64:ff9b::/96");
Expect(answers[0].Ttl == 300, $"a TTL under the ceiling is kept, got {answers[0].Ttl}");
Expect(BinaryPrimitives.ReadUInt16BigEndian(synth!.AsSpan(0)) == 0x1234, "the synthesis keeps the client's query id");

// §5.1.7: the ceiling is 600 when the negative AAAA answer carried no SOA.
var longTtl = Dns64.Synthesize(request, questionEnd, emptyAaaa,
    Msg(0, NoError, "www.example.com", DnsFormat.TypeA, A("www.example.com", 3600, "192.0.2.1")), pref);
Expect(Section(longTtl!, 0)[0].Ttl == 600, "a TTL over the ceiling is capped at 600");

// §5.1.7: a SOA in the negative answer supplies a shorter ceiling.
var soaRdata = new List<byte>();
soaRdata.AddRange(Name("ns.example.com"));
soaRdata.AddRange(Name("host.example.com"));
soaRdata.AddRange(Be32(1)); soaRdata.AddRange(Be32(2)); soaRdata.AddRange(Be32(3));
soaRdata.AddRange(Be32(4)); soaRdata.AddRange(Be32(5));
var negativeWithSoa = Msg(0, NoError, "www.example.com", DnsFormat.TypeAaaa,
    new Rec(1, "example.com", DnsFormat.TypeSoa, 30, soaRdata.ToArray()));
var soaCapped = Dns64.Synthesize(request, questionEnd, negativeWithSoa,
    Msg(0, NoError, "www.example.com", DnsFormat.TypeA, A("www.example.com", 3600, "192.0.2.1")), pref);
Expect(Section(soaCapped!, 0)[0].Ttl == 30, $"the SOA's TTL becomes the ceiling, got {Section(soaCapped!, 0)[0].Ttl}");

// §5.1.5: a CNAME chain from the AAAA answer rides along with the synthetic AAAA.
var cnameChain = Msg(0, NoError, "www.example.com", DnsFormat.TypeAaaa,
    new Rec(0, "www.example.com", DnsFormat.TypeCname, 60, Name("target.example.com")));
var withChain = Dns64.Synthesize(request, questionEnd, cnameChain, aResponse, pref);
var chainAnswers = Section(withChain!, 0);
Expect(chainAnswers.Count == 2 && chainAnswers[0].Type == DnsFormat.TypeCname && chainAnswers[1].Type == DnsFormat.TypeAaaa,
    "the CNAME is copied ahead of the synthetic AAAA");

// §5.4: an A answer with no A record synthesizes nothing.
var noA = Msg(0, NoError, "www.example.com", DnsFormat.TypeA);
Expect(Dns64.Synthesize(request, questionEnd, emptyAaaa, noA, pref) == null,
    "an empty A answer synthesizes nothing");

// --- §5.3.1 PTR redirect -----------------------------------------------------------------------------
var embedded = IPAddress.Parse("64:ff9b::c000:0201");   // 192.0.2.1 under the well-known prefix
Expect(Dns64.PtrTarget(Ip6Arpa(embedded), pref) == "1.2.0.192.in-addr.arpa",
    "a PTR inside the prefix redirects to the matching in-addr.arpa name");
Expect(Dns64.PtrTarget("www.example.com", pref) == null, "a non-ip6.arpa name is left alone");
Expect(Dns64.PtrTarget("1.2.3.ip6.arpa", pref) == null, "a name with too few nibbles is left alone");
Expect(Dns64.PtrTarget(Ip6Arpa(IPAddress.Parse("2001:db8::1")), pref) == null,
    "an address outside the prefix is left alone");

// --- Pref64 configuration ----------------------------------------------------------------------------
Expect(Pref64Config.Parse("64:ff9b::/96") != null, "a well-known prefix parses");
Expect(Pref64Config.Parse("not-a-prefix") == null, "a malformed prefix does not parse");

// --- malformed input: a parser must refuse, not crash ------------------------------------------------
// The contract is "read what fits, never throw": TryReadSections returns the records physically present
// and stops at a truncation rather than reading past the buffer. These are messages a hostile or broken
// upstream could send; the guard is that every call completes without an exception. The definite refusals
// (short header, name-pointer loop) are pinned to Failed; the rest only have to survive.
static bool Survives(Action act) { try { act(); return true; } catch { return false; } }
static byte[] Corrupt(byte[] msg, int at, byte value) { var m = msg.ToArray(); m[at] = value; return m; }

Expect(Dns64.Classify(Array.Empty<byte>()) == Dns64.Verdict.Failed, "an empty message is Failed");
Expect(Dns64.Classify(new byte[11]) == Dns64.Verdict.Failed, "an 11-octet message is Failed");

var valid = Msg(1, NoError, "x.example", DnsFormat.TypeAaaa, Aaaa("x.example", 60, V6("2001:db8::1")));
var lyingCount = Corrupt(valid, 7, 5);                 // ANCOUNT 5, one record present
var lyingRdlength = Corrupt(valid, valid.Length - 18, 0x7f);   // RDLENGTH past the end
var pointerLoop = Msg(1, NoError, "x.example", DnsFormat.TypeAaaa);
pointerLoop[12] = 0xc0; pointerLoop[13] = 0x0c;        // question name points at itself
var cutRdata = valid.AsSpan(0, valid.Length - 5).ToArray();
var badA = Corrupt(aResponse, 7, 9);

Expect(Dns64.Classify(pointerLoop) == Dns64.Verdict.Failed, "a self-referential name pointer is Failed");
Expect(Survives(() => Dns64.Classify(lyingCount)), "a lying answer count does not crash Classify");
Expect(Survives(() => Dns64.Classify(lyingRdlength)), "an RDLENGTH past the end does not crash Classify");
Expect(Survives(() => Dns64.Classify(cutRdata)), "a message cut inside the RDATA does not crash Classify");
Expect(Survives(() => Dns64.WithoutExcluded(lyingCount)), "a lying answer count does not crash WithoutExcluded");
Expect(Survives(() => Dns64.WithoutExcluded(new byte[12])), "a header-only message does not crash WithoutExcluded");
Expect(Survives(() => Dns64.Synthesize(request, questionEnd, emptyAaaa, badA, pref)), "a malformed A answer does not crash Synthesize");
Expect(Survives(() => Dns64.Synthesize(request, questionEnd, cutRdata, cutRdata, pref)), "a truncated AAAA/A does not crash Synthesize");
Expect(Survives(() => Dns64.PtrTarget(new string('1', 63) + ".ip6.arpa", pref)), "an over-long nibble label does not crash PtrTarget");

if (failures.Count > 0)
{
    Console.WriteLine($"[dns64check] FAIL ({failures.Count})");
    return 1;
}
Console.WriteLine("[dns64check] PASS - RFC 6147 classification, exclusion, synthesis, TTL ceiling, CNAME chain, PTR redirect");
return 0;

record Rec(int Section, string Name, ushort Type, uint Ttl, byte[] RData);
