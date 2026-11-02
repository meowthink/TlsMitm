using System.Buffers.Binary;
using System.Net;

namespace Router;

// RFC 6147 §5.2's Pref64::/n. §5.2 also ties this value to the translator: "The same algorithm to
// create an IPv6 address from an IPv4 address MUST be used by both a DNS64 ... and by an IPv6/IPv4
// translator", so the prefix configured here is the one the NAT64 side has to be given.
public sealed record Pref64Config(IPAddress Prefix, int PrefixLength)
{
    // RFC 6147 §5.2: "If no prefix is available, the algorithm MUST use the Well-Known Prefix
    // 64:ff9b::/96 defined in [RFC6052] to represent the IPv4 unicast address range."
    public static readonly Pref64Config WellKnown = new(IPAddress.Parse("64:ff9b::"), 96);

    public static Pref64Config? Parse(string text)
        => Pref64.TryParse(text, out var prefix, out var length) ? new Pref64Config(prefix!, length) : null;
}

// What RFC 6147 §5.1 tells a resolver to do with a AAAA query it has just had answered upstream, and
// §5.4's assembly of the response that goes back to the client. Message shaping stays in DnsFormat;
// what is here is the decision and the synthesis.
public static class Dns64
{
    // RFC 6147 §5.1.7: "If the SOA RR was not delivered with the negative response to the AAAA query,
    // then the DNS64 SHOULD use the TTL of the original A RR or 600 seconds, whichever is shorter."
    public const uint SyntheticTtlCeiling = 600;

    // RFC 3596 §2.5: "An IPv6 address is represented as a name in the IP6.ARPA domain by a sequence
    // of nibbles separated by dots with the suffix '.IP6.ARPA'."
    private const string Ip6ArpaSuffix = ".ip6.arpa";
    private const int Ip6ArpaNibbles = 32;

    public enum Verdict
    {
        // §5.1.1: "If there is (non-excluded) AAAA data available, DNS64 SHOULD NOT include synthetic
        // AAAA RRs in the response."
        Usable,
        // §5.1.4 with both kinds present: "it by default SHOULD build an answer section for a response
        // including only the AAAA record(s) that do not contain any of the addresses inside the
        // excluded ranges."
        Mixed,
        // §5.1.4: "if it receives an answer with only AAAA records containing addresses in the excluded
        // range(s), then it MUST treat the answer as though it were an empty answer".
        ExcludedOnly,
        Empty,
        // §5.1.2: "A result with RCODE=3 (Name Error) is handled according to normal DNS operation".
        NameError,
        // §5.1.2 for any other RCODE, and §5.1.3 for a timeout: "it is treated as RCODE=2 (Server
        // failure)", which §5.1.2 then treats as an empty answer section.
        Failed,
    }

    // RFC 6147 §5.1.4: "An implementation SHOULD include the ::ffff/96 network in that range by
    // default." An address there is an IPv4-mapped one, which is what makes §5.1.4's opening sentence
    // apply - "Some IPv6 addresses are not actually usable by IPv6-only hosts."
    private static readonly byte[] Ipv4Mapped = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

    public static Verdict Classify(ReadOnlySpan<byte> response)
    {
        if (response.Length < DnsFormat.HeaderLength) return Verdict.Failed;
        var rcode = BinaryPrimitives.ReadUInt16BigEndian(response.Slice(2, 2)) & 0x000F;
        if (rcode == 3) return Verdict.NameError;
        if (rcode != 0) return Verdict.Failed;
        if (!DnsFormat.TryReadSections(response, out _, out var records)) return Verdict.Failed;

        var usable = 0;
        var excluded = 0;
        foreach (var (offset, section) in records)
        {
            if (section != DnsSection.Answer) break;
            if (!TryReadFixed(response, offset, out var type, out _, out var rdata, out var rdLength)) break;
            if (type != DnsFormat.TypeAaaa) continue;
            if (response.Slice(rdata, rdLength).StartsWith(Ipv4Mapped)) excluded++;
            else usable++;
        }

        if (usable > 0) return excluded > 0 ? Verdict.Mixed : Verdict.Usable;
        return excluded > 0 ? Verdict.ExcludedOnly : Verdict.Empty;
    }

    // §5.1.4's "It MUST NOT return the offending AAAA records as part of a response", applied to every
    // section rather than only the answer: an excluded address in the additional section is as unusable
    // as one in the answer.
    public static byte[]? WithoutExcluded(ReadOnlySpan<byte> response)
    {
        if (!DnsFormat.TryReadSections(response, out var questionEnd, out var records)) return null;
        var body = new List<byte>();
        var counts = new ushort[3];
        foreach (var (offset, section) in records)
        {
            if (!TryReadFixed(response, offset, out var type, out _, out var rdata, out var rdLength)) return null;
            if (type == DnsFormat.TypeAaaa && response.Slice(rdata, rdLength).StartsWith(Ipv4Mapped)) continue;
            if (!AppendRecord(body, response, offset)) return null;
            counts[(int)section]++;
        }

        var flags = BinaryPrimitives.ReadUInt16BigEndian(response.Slice(2, 2));
        var id = BinaryPrimitives.ReadUInt16BigEndian(response.Slice(0, 2));
        return Assemble(response.Slice(DnsFormat.HeaderLength, questionEnd - DnsFormat.HeaderLength),
            body, counts, id, flags);
    }

    // RFC 6147 §5.4's assembly, for the case §5.1.6 sends us here: the AAAA query came back with nothing
    // usable and the A query came back with something. `aaaa` may be no message at all, which is what a
    // §5.1.3 timeout looks like by the time it reaches this method. Null is a source this walk cannot
    // read, or an A response with no A record in it - and §5.4 covers that case on its own: "If there is
    // an empty answer, then the DNS64 responds to the original querying client with the answer the DNS64
    // received to the original (initiator's) query."
    public static byte[]? Synthesize(ReadOnlySpan<byte> request, int questionEnd,
        ReadOnlySpan<byte> aaaa, ReadOnlySpan<byte> a, Pref64Config pref)
    {
        if (!DnsFormat.TryReadSections(a, out _, out var aRecords)) return null;

        var body = new List<byte>();
        ushort answers = 0;

        // §5.1.5: "When assembling the answer section, any chains of CNAME or DNAME RRs are included as
        // part of the answer along with the synthetic AAAA." The chain is the AAAA response's, because
        // that is the query the client's own name went through.
        if (DnsFormat.TryReadSections(aaaa, out _, out var aaaaRecords))
            foreach (var (offset, section) in aaaaRecords)
            {
                if (section != DnsSection.Answer) break;
                if (!TryReadFixed(aaaa, offset, out var type, out _, out _, out _)) return null;
                if (type is not (DnsFormat.TypeCname or DnsFormat.TypeDname)) continue;
                if (!AppendRecord(body, aaaa, offset)) return null;
                answers++;
            }

        // §5.1.7 takes the SOA's TTL from "the negative response to the AAAA query" and needs no second
        // query for it, and falls back to 600 seconds when that response carried no SOA.
        var ceiling = SoaTtl(aaaa) ?? SyntheticTtlCeiling;
        foreach (var (offset, section) in aRecords)
        {
            if (section != DnsSection.Answer) break;
            if (!TryReadARecord(a, offset, out var name, out var ttl, out var address)) continue;
            body.AddRange(name);
            AddShort(body, DnsFormat.TypeAaaa);
            AddShort(body, DnsFormat.ClassInternet);
            AddUInt(body, Math.Min(ttl, ceiling));
            AddShort(body, 16);
            body.AddRange(Pref64.Embed(pref.Prefix, pref.PrefixLength, Host.ToIpAddress(address)).GetAddressBytes());
            answers++;
        }
        if (answers == 0) return null;

        // §5.4: "The authority and additional sections are copied from the response to the final query
        // that the DNS64 performed, and used as the basis for synthesis." Nothing is added to the
        // additional section, which is what §5.3.2 requires of it.
        var counts = new ushort[3] { answers, 0, 0 };
        foreach (var (offset, section) in aRecords)
        {
            if (section == DnsSection.Answer) continue;
            if (!AppendRecord(body, a, offset)) return null;
            counts[(int)section]++;
        }

        return Assemble(request.Slice(DnsFormat.HeaderLength, questionEnd - DnsFormat.HeaderLength), body, counts,
            BinaryPrimitives.ReadUInt16BigEndian(request.Slice(0, 2)),
            BinaryPrimitives.ReadUInt16BigEndian(a.Slice(2, 2)));
    }

    // RFC 6147 §5.3.1's second option, for a PTR query whose address is inside our Pref64::/n: "the
    // DNS64 name server [synthesizes] a CNAME mapping the IP6.ARPA namespace to the corresponding
    // IN-ADDR.ARPA name". The client's next query is for that IN-ADDR.ARPA name and is answered like any
    // other. Null is §5.3.1's other case - an address that "does not match any Pref64::/n", which the
    // server "MUST process ... as though it were any other query".
    public static string? PtrTarget(string name, Pref64Config pref)
    {
        if (!name.EndsWith(Ip6ArpaSuffix, StringComparison.OrdinalIgnoreCase)) return null;
        var nibbles = name[..^Ip6ArpaSuffix.Length].Split('.');
        if (nibbles.Length != Ip6ArpaNibbles) return null;

        var bytes = new byte[16];
        for (var i = 0; i < nibbles.Length; i++)
        {
            if (nibbles[i].Length != 1) return null;
            var digit = Uri.FromHex(nibbles[i][0]);
            if (digit < 0) return null;
            // §2.5's order: "the low-order nibble is encoded first", so the first label is the last
            // nibble of the address.
            var nibble = Ip6ArpaNibbles - 1 - i;
            if (nibble % 2 == 0) bytes[nibble / 2] |= (byte)digit;
            else bytes[nibble / 2] |= (byte)(digit << 4);
        }

        if (Pref64.Extract(pref.Prefix, pref.PrefixLength, new IPAddress(bytes)) is not { } v4) return null;
        var octets = v4.GetAddressBytes();
        return $"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa";
    }

    private static uint? SoaTtl(ReadOnlySpan<byte> response)
    {
        if (!DnsFormat.TryReadSections(response, out _, out var records)) return null;
        foreach (var (offset, section) in records)
        {
            if (section == DnsSection.Additional) break;
            if (!TryReadFixed(response, offset, out var type, out var ttl, out _, out _)) return null;
            if (type == DnsFormat.TypeSoa) return ttl;
        }
        return null;
    }

    // RFC 1035 §3.2.1's fixed part, which §3.2 puts ahead of the RDATA in every record shape: NAME,
    // TYPE, CLASS, TTL, RDLENGTH. A record whose RDATA reaches past the end of the message is not one
    // this walk can copy.
    private static bool TryReadFixed(ReadOnlySpan<byte> message, int offset,
        out ushort type, out uint ttl, out int rdata, out int rdLength)
    {
        type = 0;
        ttl = 0;
        rdata = 0;
        rdLength = 0;
        var at = offset;
        if (!DnsFormat.ReadName(message, ref at, null)) return false;
        if (at + 10 > message.Length) return false;
        type = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(at, 2));
        ttl = BinaryPrimitives.ReadUInt32BigEndian(message.Slice(at + 4, 4));
        rdLength = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(at + 8, 2));
        rdata = at + 10;
        return rdata + rdLength <= message.Length;
    }

    private static bool TryReadARecord(ReadOnlySpan<byte> message, int offset,
        out List<byte> name, out uint ttl, out uint address)
    {
        name = new List<byte>();
        ttl = 0;
        address = 0;
        var at = offset;
        if (!DnsFormat.ReadName(message, ref at, name)) return false;
        if (at + 14 > message.Length) return false;
        if (BinaryPrimitives.ReadUInt16BigEndian(message.Slice(at, 2)) != DnsFormat.TypeA) return false;
        if (BinaryPrimitives.ReadUInt16BigEndian(message.Slice(at + 2, 2)) != DnsFormat.ClassInternet) return false;
        if (BinaryPrimitives.ReadUInt16BigEndian(message.Slice(at + 8, 2)) != 4) return false;
        ttl = BinaryPrimitives.ReadUInt32BigEndian(message.Slice(at + 4, 4));
        address = BinaryPrimitives.ReadUInt32BigEndian(message.Slice(at + 10, 4));
        return true;
    }

    // Copies one record into the message being built. The owner name and any name inside the RDATA are
    // written out as labels: the sections of the output are not the same length as the source's, so a
    // compression pointer that resolved there would not resolve here.
    private static bool AppendRecord(List<byte> body, ReadOnlySpan<byte> source, int offset)
    {
        var name = new List<byte>();
        var at = offset;
        if (!DnsFormat.ReadName(source, ref at, name)) return false;
        if (at + 10 > source.Length) return false;
        var type = BinaryPrimitives.ReadUInt16BigEndian(source.Slice(at, 2));
        var rdLength = BinaryPrimitives.ReadUInt16BigEndian(source.Slice(at + 8, 2));
        var rdata = at + 10;
        if (rdata + rdLength > source.Length) return false;

        var rewritten = new List<byte>();
        if (!AppendRdata(rewritten, type, source, rdata, rdLength)) return false;

        body.AddRange(name);
        body.AddRange(source.Slice(at, 8));                            // TYPE, CLASS and TTL as they came
        AddShort(body, (ushort)rewritten.Count);
        body.AddRange(rewritten);
        return true;
    }

    // The RDATA shapes RFC 1035 §3.3 defines with a domain name inside them, plus the two later RFCs
    // that added one: RFC 2782's SRV and RFC 6672's DNAME, whose §2.1 requires the target to be "sent
    // in uncompressed form" anyway. Every other type is copied as it came.
    private static bool AppendRdata(List<byte> body, ushort type, ReadOnlySpan<byte> source, int rdata, int length)
    {
        var end = rdata + length;
        var offset = rdata;
        switch (type)
        {
            case DnsFormat.TypeCname:
            case DnsFormat.TypeDname:
            case DnsFormat.TypeNs:
            case DnsFormat.TypePtr:
                return DnsFormat.ReadName(source, ref offset, body) && offset == end;
            case DnsFormat.TypeMx:
                if (!CopyLiteral(body, source, ref offset, end, 2)) return false;
                return DnsFormat.ReadName(source, ref offset, body) && offset == end;
            case DnsFormat.TypeSrv:
                if (!CopyLiteral(body, source, ref offset, end, 6)) return false;
                return DnsFormat.ReadName(source, ref offset, body) && offset == end;
            case DnsFormat.TypeSoa:
                if (!DnsFormat.ReadName(source, ref offset, body)) return false;
                if (!DnsFormat.ReadName(source, ref offset, body)) return false;
                return CopyLiteral(body, source, ref offset, end, 20) && offset == end;
            default:
                body.AddRange(source.Slice(rdata, length));
                return true;
        }
    }

    private static bool CopyLiteral(List<byte> body, ReadOnlySpan<byte> source, ref int offset, int end, int count)
    {
        if (offset + count > end || offset + count > source.Length) return false;
        body.AddRange(source.Slice(offset, count));
        offset += count;
        return true;
    }

    private static byte[] Assemble(ReadOnlySpan<byte> question, List<byte> body, ushort[] counts,
        ushort id, ushort flags)
    {
        var message = new byte[DnsFormat.HeaderLength + question.Length + body.Count];
        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(0, 2), id);
        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(2, 2), flags);
        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(4, 2), 1);
        for (var section = 0; section < 3; section++)
            BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(6 + section * 2, 2), counts[section]);
        question.CopyTo(message.AsSpan(DnsFormat.HeaderLength));
        body.CopyTo(message, DnsFormat.HeaderLength + question.Length);
        return message;
    }

    private static void AddShort(List<byte> body, ushort value)
    {
        var bytes = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        body.AddRange(bytes);
    }

    private static void AddUInt(List<byte> body, uint value)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        body.AddRange(bytes);
    }
}
