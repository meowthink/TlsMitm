using System.Buffers.Binary;
using System.Text;

namespace Router;

// RFC 1035 §3.4.1 defines the one record type this server answers about itself.
public sealed record DnsQuestion(ushort Type, ushort Class, string Name)
{
    public string CacheKey => Name.ToLowerInvariant() + "/" + Type;
}

public sealed record DnsQuery(DnsQuestion Question, ushort Id, int QuestionEnd);

// The three sections after the question, in the order RFC 1035 §4.1.1 puts their counts in the header.
public enum DnsSection { Answer = 0, Authority = 1, Additional = 2 }

// Parse a query, build an answer, decide what to ask upstream. No sockets in here: the transport is
// injected, which is what lets tests/servcheck feed a canned upstream response and judge the cache and
// the truncation rule with no network at all.
public static class DnsFormat
{
    public const int HeaderLength = 12;
    public const ushort ClassInternet = 1;
    // RFC 1035 §3.2.2's TYPE values, and the three later RFCs that added the ones this server has to
    // tell apart: RFC 3596 §2.1 for AAAA ("The IANA assigned value of the type is 28"), RFC 6672 §2.1
    // for DNAME ("type code 39"), RFC 2782 for SRV ("whose DNS type code is 33").
    public const ushort TypeA = 1;
    public const ushort TypeNs = 2;
    public const ushort TypeCname = 5;
    public const ushort TypeSoa = 6;
    public const ushort TypePtr = 12;
    public const ushort TypeMx = 15;
    public const ushort TypeAaaa = 28;
    public const ushort TypeSrv = 33;
    public const ushort TypeDname = 39;
    public const ushort TypeSvcb = 64;
    public const ushort TypeHttps = 65;
    // RFC 9848 §3: the "ech" SvcParamKey "conveys the ECH configuration", and the RFC's IANA table
    // gives it the number 5. RFC 9460 §2.4.3 is what makes a rewrite of the key sufficient:
    // "clients MUST ignore any SvcParam that they do not recognize."
    public const ushort SvcParamEch = 5;
    // RFC 9460 §14.3.2 puts the private-use SvcParamKeys in 65280-65534.
    public const ushort SvcParamPrivateUse = 65280;
    // RFC 1035 §4.2.1: "Messages carried by UDP are restricted to 512 bytes... Longer messages are
    // truncated and the TC bit is set in the header."
    public const int UdpMessageLimit = 512;

    private const ushort FlagResponse = 0x8000;
    private const ushort FlagAuthoritative = 0x0400;
    private const ushort FlagTruncated = 0x0200;
    private const ushort FlagRecursionDesired = 0x0100;
    private const ushort FlagRecursionAvailable = 0x0080;

    public static bool TryReadQuery(ReadOnlySpan<byte> message, out DnsQuery query)
    {
        query = null!;
        if (message.Length < HeaderLength) return false;

        var id = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(0, 2));
        var flags = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(2, 2));
        // Only a plain query is answerable: a response, or an opcode other than QUERY, is not something
        // a stub forwarder was asked to do anything with.
        if ((flags & FlagResponse) != 0) return false;
        if ((flags >> 11 & 0x0F) != 0) return false;
        if (BinaryPrimitives.ReadUInt16BigEndian(message.Slice(4, 2)) != 1) return false;

        if (!TryReadName(message, HeaderLength, out var name, out var afterName)) return false;
        if (afterName + 4 > message.Length) return false;
        var type = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(afterName, 2));
        var cls = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(afterName + 2, 2));
        if (cls != ClassInternet) return false;

        query = new DnsQuery(new DnsQuestion(type, cls, name), id, afterName + 4);
        return true;
    }

    // A question name is read as length-prefixed labels only. Following a pointer needs the rest of the
    // message to be a thing this server is willing to decode, and a query is not: it is refused rather
    // than guessed at.
    public static bool TryReadName(ReadOnlySpan<byte> message, int offset, out string name, out int next)
    {
        var labels = new List<string>();
        while (true)
        {
            if (offset >= message.Length) { name = ""; next = 0; return false; }
            var length = message[offset];
            if (length == 0) { offset++; break; }
            if ((length & 0xC0) != 0) { name = ""; next = 0; return false; }
            if (offset + 1 + length > message.Length) { name = ""; next = 0; return false; }
            if (length > 63) { name = ""; next = 0; return false; }
            labels.Add(Encoding.ASCII.GetString(message.Slice(offset + 1, length)));
            offset += 1 + length;
        }
        name = string.Join('.', labels);
        next = offset;
        return labels.Count > 0;
    }

    public static bool IsTruncated(ReadOnlySpan<byte> message)
        => message.Length >= HeaderLength
           && (BinaryPrimitives.ReadUInt16BigEndian(message.Slice(2, 2)) & FlagTruncated) != 0;

    public static bool HasAnswers(ReadOnlySpan<byte> message)
        => message.Length >= HeaderLength && BinaryPrimitives.ReadUInt16BigEndian(message.Slice(6, 2)) > 0;

    // The offset the question ends at and the one each resource record begins at, walking the three
    // sections in the order RFC 1035 §4.1.1 counts them. A record whose bytes will not walk ends the walk
    // where it is: what came before it is all a caller can claim to have found.
    public static bool TryReadSections(ReadOnlySpan<byte> message, out int questionEnd,
        out List<(int Offset, DnsSection Section)> records)
    {
        records = new List<(int Offset, DnsSection Section)>();
        questionEnd = 0;
        if (message.Length < HeaderLength) return false;

        var questions = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(4, 2));
        var offset = HeaderLength;
        for (var i = 0; i < questions; i++)
        {
            if (!SkipName(message, ref offset) || offset + 4 > message.Length) return false;
            offset += 4;
        }
        questionEnd = offset;

        for (var section = 0; section < 3; section++)
        {
            var count = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(6 + section * 2, 2));
            for (var i = 0; i < count; i++)
            {
                var start = offset;
                if (!SkipName(message, ref offset) || offset + 10 > message.Length) return true;
                // TYPE, CLASS and TTL precede RDLENGTH in every record shape, §3.2's own fixed part.
                var rdLength = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset + 8, 2));
                offset += 10 + rdLength;
                if (offset > message.Length) return true;
                records.Add((start, (DnsSection)section));
            }
        }
        return true;
    }

    // RFC 1035 §4.2.1: "Messages carried by UDP are restricted to 512 bytes... Longer messages are
    // truncated and the TC bit is set in the header." The cut lands between whole records and the three
    // counts are rewritten to say what is still physically present, because a header that promises a
    // record the bytes do not carry is a message no client can finish parsing. Records go from the end, so
    // what is kept is the beginning of the answer rather than a scatter of the sections.
    // Null is the case nothing can be cut to: the question this answer echoes is itself over the ceiling.
    public static byte[]? TruncateForUdp(ReadOnlySpan<byte> message)
    {
        if (message.Length <= UdpMessageLimit) return message.ToArray();
        if (!TryReadSections(message, out var questionEnd, out var records) || questionEnd > UdpMessageLimit)
            return null;

        var cut = records.Count == 0 ? questionEnd : message.Length;
        var kept = new int[3];
        for (var i = 0; i < records.Count; i++)
        {
            var end = i + 1 < records.Count ? records[i + 1].Offset : message.Length;
            if (end <= UdpMessageLimit)
            {
                kept[(int)records[i].Section]++;
                continue;
            }
            cut = records[i].Offset;
            break;
        }

        var reply = new byte[cut];
        message.Slice(0, cut).CopyTo(reply);
        BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(2, 2),
            (ushort)(BinaryPrimitives.ReadUInt16BigEndian(reply.AsSpan(2, 2)) | FlagTruncated));
        for (var section = 0; section < 3; section++)
            BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(6 + section * 2, 2), (ushort)kept[section]);
        return reply;
    }

    public static byte[] RewriteId(ReadOnlySpan<byte> message, ushort id)
    {
        var copy = message.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(copy.AsSpan(0, 2), id);
        return copy;
    }

    // RFC 1035 §3.2.1 defines TTL per resource record: "specifies the time interval that the resource
    // record may be cached before the source of the information should again be consulted". A stored
    // response cannot therefore outlive the shortest TTL among the records it carries.
    public static uint? ShortestAnswerTtl(ReadOnlySpan<byte> message)
    {
        if (message.Length < HeaderLength) return null;
        var answers = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(6, 2));
        if (answers == 0) return null;
        var offset = HeaderLength;
        if (!SkipName(message, ref offset)) return null;
        offset += 4;

        uint? shortest = null;
        for (ushort i = 0; i < answers && offset < message.Length; i++)
        {
            if (!SkipName(message, ref offset) || offset + 10 > message.Length) break;
            var ttl = BinaryPrimitives.ReadUInt32BigEndian(message.Slice(offset + 4, 4));
            var rdLength = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset + 8, 2));
            shortest = shortest is null ? ttl : Math.Min(shortest.Value, ttl);
            offset += 10 + rdLength;
        }
        return shortest;
    }

    // RFC 9848 §3 is how a client learns its ECH configuration: the HTTPS record's "ech" SvcParam (key
    // 5) "conveys the ECH configuration", and a client that never receives one has nothing to put in its
    // ClientHello. The handshake then names its host in the clear, which is the case RFC 9849 §8.1.2 keeps
    // working "even in cases where the server supports ECH but the proxy does not"; measured on this host,
    // the opposite - a client that keeps its configuration - is the blind-relay case: the proxy terminates,
    // the client sends nothing, and the session ends up on the real certificate.
    //
    // The key is rewritten rather than removed, and that is the whole trick: every length in the message
    // stays where the far end wrote it, so no offset after the change moves and no compression pointer
    // into the message is invalidated. RFC 9460 §2.4.3 is what makes the rewrite enough - "clients MUST
    // ignore any SvcParam that they do not recognize" - and §14.3.2 puts 65280-65534 at the client's
    // disposal as private use. Returns how many parameters were rewritten, so a caller can say so.
    public static int NeutralizeEch(Span<byte> message)
    {
        if (message.Length < HeaderLength) return 0;

        var offset = HeaderLength;
        var questions = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(4, 2));
        for (var i = 0; i < questions; i++)
        {
            if (!SkipName(message, ref offset) || offset + 4 > message.Length) return 0;
            offset += 4;
        }

        var rewritten = 0;
        for (var section = 0; section < 3; section++)
        {
            var count = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(6 + section * 2, 2));
            for (var i = 0; i < count; i++)
            {
                if (!SkipName(message, ref offset) || offset + 10 > message.Length) return rewritten;
                var type = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset, 2));
                // TYPE, CLASS and TTL precede RDLENGTH, §3.2's own fixed part.
                var rdLength = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset + 8, 2));
                var rdata = offset + 10;
                if (rdata + rdLength > message.Length) return rewritten;
                if (type is TypeSvcb or TypeHttps)
                    rewritten += NeutralizeServiceParams(message.Slice(rdata, rdLength));
                offset = rdata + rdLength;
            }
        }
        return rewritten;
    }

    // RFC 9460 §2.2 lays the RDATA out as a two-octet priority, the TargetName and then the SvcParams,
    // each of those a two-octet key, a two-octet length and that many octets of value. The TargetName is
    // stated to be "uncompressed", so a pointer where a label belongs is not a record this walk reads.
    private static int NeutralizeServiceParams(Span<byte> rdata)
    {
        if (rdata.Length < 3) return 0;
        var offset = 2;
        while (true)
        {
            if (offset >= rdata.Length) return 0;
            var length = rdata[offset];
            if (length == 0) { offset++; break; }
            if ((length & 0xC0) != 0 || offset + 1 + length > rdata.Length) return 0;
            offset += 1 + length;
        }

        var rewritten = 0;
        while (offset + 4 <= rdata.Length)
        {
            var key = BinaryPrimitives.ReadUInt16BigEndian(rdata.Slice(offset, 2));
            var length = BinaryPrimitives.ReadUInt16BigEndian(rdata.Slice(offset + 2, 2));
            if (offset + 4 + length > rdata.Length) return rewritten;
            if (key == SvcParamEch)
            {
                BinaryPrimitives.WriteUInt16BigEndian(rdata.Slice(offset, 2), SvcParamPrivateUse);
                rewritten++;
            }
            offset += 4 + length;
        }
        return rewritten;
    }

    // Walks a name that may contain a compression pointer, which is what RFC 1035 §4.1.4 describes: a
    // two-octet pointer whose low 14 bits are an offset back into the message. The offset has to come
    // back at the record's own fields, two octets past the pointer, rather than at the end of the name
    // the pointer led to - that is why this is not the same as reading one.
    private static bool SkipName(ReadOnlySpan<byte> message, ref int offset) => ReadName(message, ref offset, null);

    // The same walk with the labels written out: `body` gets the length-prefixed labels and the closing
    // zero octet, with every pointer resolved. A message being assembled does not have this one's layout,
    // so a pointer copied across into it would name something else.
    internal static bool ReadName(ReadOnlySpan<byte> message, ref int offset, List<byte>? body)
    {
        var resume = -1;
        var steps = 0;
        while (offset < message.Length)
        {
            var length = message[offset];
            if (length == 0)
            {
                body?.Add(0);
                offset = resume >= 0 ? resume : offset + 1;
                return offset <= message.Length;
            }
            if ((length & 0xC0) == 0xC0)
            {
                if (offset + 2 > message.Length) return false;
                var target = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset, 2)) & 0x3FFF;
                // Only backwards: a pointer to itself or further on is a loop the walk cannot end.
                if (target >= offset) return false;
                if (resume < 0) resume = offset + 2;
                offset = target;
                continue;
            }
            if (offset + 1 + length > message.Length) return false;
            if (length > 63) return false;
            if (body is not null)
            {
                body.Add(length);
                body.AddRange(message.Slice(offset + 1, length));
            }
            offset += 1 + length;
            if (++steps > 128) return false;                              // a name cannot be that long
        }
        return false;
    }

    public static byte[] BuildQuery(ushort id, string name, ushort type)
    {
        var body = new List<byte>();
        WriteName(body, name);
        AddShort(body, type);
        AddShort(body, ClassInternet);

        var message = new byte[HeaderLength + body.Count];
        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(0, 2), id);
        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(2, 2), FlagRecursionDesired);
        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(4, 2), 1);
        body.CopyTo(message, HeaderLength);
        return message;
    }

    // An authoritative answer about something this server knows on its own: the question is echoed and
    // one A record follows, whose NAME is a pointer to the question's name - legal in an answer, and
    // what RFC 1035 §4.1.4 describes.
    public static byte[] BuildAnswer(ReadOnlySpan<byte> query, int questionEnd, uint ttl, uint address)
    {
        var answer = new List<byte> { 0xC0, 0x0C };
        AddShort(answer, TypeA);
        AddShort(answer, ClassInternet);
        var ttlBytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(ttlBytes, ttl);
        answer.AddRange(ttlBytes);
        answer.AddRange([0x00, 0x04]);
        answer.AddRange(AddressBytes(address));
        return Authoritative(query, questionEnd, answer);
    }

    // The same shape with a CNAME instead, whose RDATA is RFC 1035 §3.3.4's "A <domain-name> which
    // specifies the canonical or primary name for the owner". The target is written as labels rather
    // than as a pointer into this message: it names something the question does not.
    public static byte[] BuildCnameAnswer(ReadOnlySpan<byte> query, int questionEnd, uint ttl, string target)
    {
        var answer = new List<byte> { 0xC0, 0x0C };
        AddShort(answer, TypeCname);
        AddShort(answer, ClassInternet);
        AddUInt(answer, ttl);
        var rdata = new List<byte>();
        WriteName(rdata, target);
        AddShort(answer, (ushort)rdata.Count);
        answer.AddRange(rdata);
        return Authoritative(query, questionEnd, answer);
    }

    private static byte[] Authoritative(ReadOnlySpan<byte> query, int questionEnd, List<byte> answer)
    {
        var question = query[HeaderLength..questionEnd];
        var message = new byte[HeaderLength + question.Length + answer.Count];
        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(0, 2),
            BinaryPrimitives.ReadUInt16BigEndian(query.Slice(0, 2)));
        var queryFlags = BinaryPrimitives.ReadUInt16BigEndian(query.Slice(2, 2));
        var flags = (ushort)(FlagResponse | FlagAuthoritative | FlagRecursionAvailable);
        if ((queryFlags & FlagRecursionDesired) != 0) flags |= FlagRecursionDesired;
        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(2, 2), flags);
        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(4, 2), 1);
        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(6, 2), 1);
        question.CopyTo(message.AsSpan(HeaderLength));
        answer.CopyTo(message.AsSpan(HeaderLength + question.Length));
        return message;
    }

    public static byte[] AddressBytes(uint address)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, address);
        return bytes;
    }

    private static void WriteName(List<byte> body, string name)
    {
        foreach (var label in name.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            if (bytes.Length > 63) throw new FormatException($"DNS label longer than 63 octets: {label}");
            body.Add((byte)bytes.Length);
            body.AddRange(bytes);
        }
        body.Add(0);
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

// The cache and the forwarding decision, with the local names that come out of the DHCP pool mixed in.
public sealed class DnsServer
{
    private readonly Func<byte[], bool, byte[]?> _transport;
    private readonly Func<DateTime> _now;
    private readonly Func<string, uint?> _localAddress;
    private readonly Pref64Config? _pref64;
    private readonly Dictionary<string, (byte[] Message, DateTime UsableUntil)> _cache = new();
    private readonly object _gate = new();
    private int _nextUpstreamId;

    // A local answer is held for a short fixed time: the address it names can be rebound the moment a
    // lease expires, and the reverse mapping is only as current as the prefix it was derived from.
    public const uint LocalAnswerTtl = 30;

    public DnsServer(Func<byte[], bool, byte[]?> transport, Func<string, uint?> localAddress,
        Func<DateTime>? now = null, Pref64Config? pref64 = null)
    {
        _transport = transport;
        _localAddress = localAddress;
        _now = now ?? (() => DateTime.UtcNow);
        _pref64 = pref64;
    }

    public int CacheCount
    {
        get { lock (_gate) return _cache.Count; }
    }

    public event Action<string, ushort, string>? Queried;

    // The client is its address in text rather than the four-octet form the v4 side of this program uses
    // everywhere else: one resolver answers both families, and the identity is only ever printed. Reading
    // a v6 endpoint's first four octets as an address - which Host.ToBigEndian does without complaint -
    // would put a number in the log that names nothing.
    public bool TryRespond(ReadOnlySpan<byte> request, string client, out byte[]? reply)
    {
        reply = null;
        if (!DnsFormat.TryReadQuery(request, out var query)) return false;

        var question = query.Question;
        Queried?.Invoke(question.Name, question.Type, client);

        // A name this pool handed out is answered from the lease table and never leaves the host: that
        // is what makes a device addressable by the hostname it reported in option 12.
        var first = question.Name.Split('.')[0];
        if (question.Type == DnsFormat.TypeA && _localAddress(first) is uint local)
        {
            reply = DnsFormat.BuildAnswer(request, query.QuestionEnd, LocalAnswerTtl, local);
            return true;
        }

        // RFC 6147 §5.3.1: a PTR for an address inside our own Pref64::/n is answered here rather than
        // sent upstream, whose reverse tree has never heard of that address. An address outside it is
        // §5.3.1's other case and goes on its way untouched.
        if (question.Type == DnsFormat.TypePtr && _pref64 is { } prefix
            && Dns64.PtrTarget(question.Name, prefix) is { } target)
        {
            reply = DnsFormat.BuildCnameAnswer(request, query.QuestionEnd, LocalAnswerTtl, target);
            return true;
        }

        // The gate is the cache's own table, not this server's question. The upstream exchange happens
        // outside it: a resolver that never answers one question must not hold every other client's
        // question behind it for the length of the transport's timeout, which is exactly what taking the
        // lock around the whole of this method did.
        var key = question.CacheKey;
        var now = _now();
        lock (_gate)
        {
            if (_cache.TryGetValue(key, out var cached) && cached.UsableUntil > now)
            {
                reply = DnsFormat.RewriteId(cached.Message, query.Id);
                return true;
            }
        }

        var upstream = AskUpstream(question.Name, question.Type);
        if (question.Type == DnsFormat.TypeAaaa && _pref64 is { } pref64)
            upstream = SynthesizeAaaa(request, query, pref64, upstream);
        if (upstream is null) return false;

        // Before the cache, so the stored copy is the one with no configuration in it and a cache hit
        // cannot hand a later client what this answer just took away.
        var neutralised = DnsFormat.NeutralizeEch(upstream);
        if (neutralised > 0)
            Console.WriteLine($"[Router] dns {question.Name}: {neutralised} ech parameter(s) neutralised");

        // Only a real answer is stored. A NoError-with-no-answers or an error reply goes straight back
        // uncached: negative caching is RFC 2308, which this server does not implement.
        if (DnsFormat.HasAnswers(upstream) && DnsFormat.ShortestAnswerTtl(upstream) is uint ttl && ttl > 0)
        {
            var usableUntil = _now() + TimeSpan.FromSeconds(ttl);
            lock (_gate) _cache[key] = (upstream, usableUntil);
        }

        reply = DnsFormat.RewriteId(upstream, query.Id);
        return true;
    }

    // RFC 6147 §5.1's whole decision, for the one query type it changes. `aaaa` is what came back for
    // the client's own question, and it may be nothing at all: §5.1.3 turns a timeout into RCODE=2, and
    // §5.1.2 turns any RCODE other than 3 into "as though the RCODE were 0 ... and the answer section
    // were empty", which is a synthesis case like any other.
    private byte[]? SynthesizeAaaa(ReadOnlySpan<byte> request, DnsQuery query, Pref64Config pref, byte[]? aaaa)
    {
        var verdict = aaaa is null ? Dns64.Verdict.Failed : Dns64.Classify(aaaa);
        switch (verdict)
        {
            // §5.1.1: real AAAA data is returned "as per normal DNS semantics". §5.1.2: RCODE=3 "is
            // handled according to normal DNS operation".
            case Dns64.Verdict.Usable:
            case Dns64.Verdict.NameError:
                return aaaa;
        }

        // §5.1.4, with a usable record among the offending ones: the answer section built from what is
        // left "is used in the assembly of a response as detailed in Section 5.4". §5.1.1 then keeps the
        // A query from being asked at all - "MUST NOT synthesize AAAA RRs when real AAAA RRs exist" - and
        // the records that remain are real ones.
        if (verdict is Dns64.Verdict.Mixed)
            return Dns64.WithoutExcluded(aaaa!) ?? aaaa;

        // §5.1.4's other case, an answer of nothing but excluded addresses, "MUST [be treated] as though
        // it were an empty answer", which is where §5.1.6 starts.
        var basis = verdict is Dns64.Verdict.ExcludedOnly ? Dns64.WithoutExcluded(aaaa!) ?? aaaa : aaaa;

        // §5.1.6: the A query is what the synthesis is based on, and an empty or unanswerable one leaves
        // §5.4's rule in charge - "the DNS64 responds to the original querying client with the answer the
        // DNS64 received to the original (initiator's) query".
        if (AskUpstream(query.Question.Name, DnsFormat.TypeA) is not { } a) return basis;
        return Dns64.Synthesize(request, query.QuestionEnd, basis, a, pref) ?? basis;
    }

    private byte[]? AskUpstream(string name, ushort type)
    {
        // Every caller draws from the same counter: the UDP and the TCP listener answer at once now, and
        // two queries carrying one id are the same question to the receive loop that dispatches by it.
        var id = (ushort)Interlocked.Increment(ref _nextUpstreamId);
        var message = DnsFormat.BuildQuery(id, name, type);
        var answer = _transport(message, false);

        // Truncation on UDP is answered the way §4.2.1 points at: the same question over TCP, where
        // §4.2.2 puts a two-octet length in front of the message instead of the 512-octet ceiling.
        if (answer is not null && DnsFormat.IsTruncated(answer))
        {
            var whole = _transport(message, true);
            if (whole is not null) answer = whole;
        }
        return answer;
    }

    public void Sweep()
    {
        var now = _now();
        // The cache's own gate: this empties the very table TryRespond reads and writes. A question in
        // its upstream exchange is not holding it, so a sweep can run between two answers.
        lock (_gate)
            foreach (var key in _cache.Where(kv => kv.Value.UsableUntil <= now).Select(kv => kv.Key).ToArray())
                _cache.Remove(key);
    }
}
