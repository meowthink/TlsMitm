using System.Text;

namespace HelloFingerprint;

/// <summary>
/// A TLS ClientHello read off the wire, plus the two fingerprints computed from it.
/// JA3: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats in the order the hello
/// carries them, MD5 over that string. JA4: FoxIO's JA4 specification, sections a, b and c.
/// Both ignore GREASE, whose code points RFC 8701 §3 reserves as any value with equal high and low
/// nibbles ending in 0xa.
/// </summary>
public sealed class ClientHello
{
    public int HelloVersion { get; private init; }
    public int[] Ciphers { get; private init; } = [];
    public int[] Extensions { get; private init; } = [];
    public int[] Groups { get; private init; } = [];
    public int[] PointFormats { get; private init; } = [];
    public int[] SignatureAlgorithms { get; private init; } = [];
    public string? ServerName { get; private init; }
    public IReadOnlyList<byte[]> Alpn { get; private init; } = [];
    public int? MaxSupportedVersion { get; private init; }
    public bool Ech { get; private init; }

    public static bool IsGrease(int value) => (value & 0xf) == 0xa && (value >> 8) == (value & 0xff);

    /// <summary>The span must start at a TLS record header (content type 22) and hold the whole hello.</summary>
    public static ClientHello? Parse(ReadOnlySpan<byte> record)
    {
        if (record.Length < 6 || record[0] != 0x16 || record[5] != 0x01) return null;
        // The record length field says how much of this buffer the hello occupies; anything beyond it
        // is a later record and none of this parse's business.
        var recordLength = Be16(record[3..]);
        if (recordLength > record.Length - 5) return null;
        record = record[..(5 + recordLength)];
        if (record.Length < 9) return null;

        // A client may coalesce the hello with a later handshake message in one record, so the message
        // length, not the record length, bounds what this parse reads.
        var message = (record[6] << 16) | (record[7] << 8) | record[8];
        if (message < 2 || message > record.Length - 9) return null;
        record = record[..(9 + message)];
        if (record.Length < 11) return null;

        var p = 9;
        var helloVersion = Be16(record[p..]); p += 2 + 32;   // legacy version + random
        if (record.Length < p + 1) return null;
        p += 1 + record[p];                                   // opaque SessionID<0..32>
        if (record.Length < p + 2) return null;
        var cipherBytes = Be16(record[p..]); p += 2;
        if (record.Length < p + cipherBytes + 1) return null;
        var ciphers = ReadPairs(record.Slice(p, cipherBytes)); p += cipherBytes;
        var compBytes = record[p]; p += 1;
        if (record.Length < p + compBytes + 2) return null;
        p += compBytes;                                       // compression methods
        var extBytes = Be16(record[p..]); p += 2;
        if (record.Length < p + extBytes) return null;

        var parts = new HelloParts { Ciphers = ciphers };
        var exts = record.Slice(p, extBytes);
        while (exts.Length >= 4)
        {
            var type = Be16(exts);
            var len = Be16(exts[2..]);
            if (exts.Length < 4 + len) return null;
            parts.Add(type, exts.Slice(4, len));
            exts = exts.Slice(4 + len);
        }
        if (!exts.IsEmpty) return null;

        return new ClientHello
        {
            HelloVersion = helloVersion,
            Ciphers = parts.Ciphers,
            Extensions = [.. parts.Extensions],
            Groups = [.. parts.Groups],
            PointFormats = [.. parts.PointFormats],
            SignatureAlgorithms = [.. parts.SigAlgs],
            ServerName = parts.Sni,
            Alpn = parts.Alpn,
            MaxSupportedVersion = parts.MaxVersion,
            Ech = parts.Ech,
        };
    }

    private static int Be16(ReadOnlySpan<byte> s) => (s[0] << 8) | s[1];

    private static int[] ReadPairs(ReadOnlySpan<byte> data)
    {
        var list = new List<int>();
        for (var i = 0; i + 2 <= data.Length; i += 2)
        {
            var v = Be16(data[i..]);
            if (!IsGrease(v)) list.Add(v);
        }
        return [.. list];
    }

    private sealed class HelloParts
    {
        public const int EncryptedClientHello = 0xfe0d;

        public int[] Ciphers = [];
        public readonly List<int> Extensions = [];
        public readonly List<int> Groups = [];
        public readonly List<int> PointFormats = [];
        public readonly List<int> SigAlgs = [];
        public readonly List<byte[]> Alpn = [];
        public string? Sni;
        public int? MaxVersion;
        public bool Ech;

        public void Add(int type, ReadOnlySpan<byte> body)
        {
            if (!IsGrease(type)) Extensions.Add(type);
            switch (type)
            {
                case 0x000a:   // supported_groups, RFC 8446 §4.2.7
                    Groups.AddRange(Pairs(body));
                    break;
                case 0x000b when body.Length >= 1:   // ec_point_formats: one length byte, then one per format
                    for (var i = 1; i <= Math.Min(body[0], body.Length - 1); i++)
                    {
                        if (!IsGrease(body[i])) PointFormats.Add(body[i]);
                    }
                    break;
                case 0x000d:   // signature_algorithms, RFC 8446 §4.2.3
                    SigAlgs.AddRange(Pairs(body));
                    break;
                case 0x0000 when body.Length >= 5:   // server_name, RFC 6066 §3
                    var nameLen = Math.Min(Be16(body[3..]), body.Length - 5);
                    if (body[2] == 0) Sni = Encoding.ASCII.GetString(body.Slice(5, nameLen));
                    break;
                case 0x0010 when body.Length >= 2:   // protocol_list, RFC 7301 §4
                    var list = body[2..Math.Min(2 + Be16(body), body.Length)];
                    while (list.Length >= 1)
                    {
                        var n = Math.Min(list[0], list.Length - 1);
                        Alpn.Add(list.Slice(1, n).ToArray());
                        list = list.Slice(1 + n);
                    }
                    break;
                case 0x002b when body.Length >= 1:   // supported_versions, RFC 8446 §4.2.1: one length byte
                    var versions = body[1..Math.Min(1 + body[0], body.Length)];
                    foreach (var v in ReadPairs(versions))
                        if (MaxVersion is null || v > MaxVersion) MaxVersion = v;
                    break;
                case EncryptedClientHello:
                    Ech = true;
                    break;
            }

            // The two 2-byte-element lists in a hello are both opaque <2..2^16-1> followed by the
            // elements, so one reader covers every case that needs one.
            static int[] Pairs(ReadOnlySpan<byte> prefixed) => prefixed.Length < 2
                ? []
                : ReadPairs(prefixed[2..Math.Min(2 + Be16(prefixed), prefixed.Length)]);
        }
    }

    // ---- JA3 ----

    public string Ja3String() => string.Join(',',
        HelloVersion,
        Join(Ciphers),
        Join(Extensions),
        Join(Groups),
        Join(PointFormats));

    public string Ja3() => Ja4Format.Md5(Ja3String());

    /// <summary>
    /// Not a variant the JA3 document defines. A client that shuffles its extension order (Chrome since
    /// 110) hashes differently per connection, so comparing one fixed string against a cluster needs the
    /// sorted form; this is that sorted form, kept beside the wire-order value.
    /// </summary>
    public string Ja3SortedExtensions()
    {
        var sorted = Sorted(Extensions);
        return string.Join(',', HelloVersion, Join(Ciphers), Join(sorted), Join(Groups), Join(PointFormats));
    }

    public string Ja3SortedHash() => Ja4Format.Md5(Ja3SortedExtensions());

    private static string Join(int[] values) => string.Join('-', values);

    // ---- JA4 ----
    // Section a counts every extension, SNI and ALPN included; section c drops those two precisely
    // because a is already carrying them.

    public string Ja4()
    {
        var version = MaxSupportedVersion ?? HelloVersion;
        return $"{SectionA(version)}_{CipherHash()}_{ExtensionHash()}";
    }

    public string Ja4Raw()
    {
        var version = MaxSupportedVersion ?? HelloVersion;
        return $"{SectionA(version)}_{Ja4Format.HexList(Ciphers)}_{Ja4Format.HexList(HashedExtensions())}_{Ja4Format.HexList(SignatureAlgorithms)}";
    }

    private string SectionA(int version)
    {
        var first = Alpn.Count > 0 ? Alpn[0] : null;
        var alpn = first is { Length: > 0 } value ? Ja4Format.AlpnCode(value) : "00";
        return "t" + Ja4Format.VersionCode(version)
            + (ServerName != null ? "d" : "i")
            + Math.Min(Ciphers.Length, 99).ToString("00")
            + Math.Min(Extensions.Length, 99).ToString("00")
            + alpn;
    }

    private string CipherHash() => Ciphers.Length == 0
        ? "000000000000"
        : Ja4Format.Sha12(Ja4Format.HexList(Sorted(Ciphers)));

    private string ExtensionHash()
    {
        var hashed = HashedExtensions();
        if (hashed.Length == 0) return "000000000000";
        var text = Ja4Format.HexList(Sorted(hashed));
        if (SignatureAlgorithms.Length > 0) text += "_" + Ja4Format.HexList(SignatureAlgorithms);
        return Ja4Format.Sha12(text);
    }

    private int[] HashedExtensions() => [.. Extensions.Where(e => e is not (0x0000 or 0x0010))];

    private static int[] Sorted(int[] values)
    {
        var copy = (int[])values.Clone();
        Array.Sort(copy);
        return copy;
    }

    public override string ToString()
    {
        var alpn = Alpn.Count == 0 ? "(none)" : string.Join(", ", Alpn.Select(Encoding.ASCII.GetString));
        return string.Join(Environment.NewLine,
        [
            $"hello version      : 0x{HelloVersion:x4} ({HelloVersion})" +
                (MaxSupportedVersion is int sv ? $" supported_versions max 0x{sv:x4}" : ""),
            $"ciphers ({Ciphers.Length})  : {Join(Ciphers)}",
            $"extensions ({Extensions.Length}) : {Join(Extensions)}  wire-order",
            $"groups             : {Join(Groups)}",
            $"point formats      : {Join(PointFormats)}",
            $"signature algorithms ({SignatureAlgorithms.Length}) : {Join(SignatureAlgorithms)}",
            $"sni                : {ServerName ?? "(none)"}",
            $"alpn               : {alpn}",
            $"ech                : {(Ech ? "present" : "absent")}",
            "",
            $"JA3 string         : {Ja3String()}",
            $"JA3                : {Ja3()}",
            $"JA3 sorted-ext     : {Ja3SortedExtensions()}",
            $"JA3 sorted hash    : {Ja3SortedHash()}",
            $"JA4                : {Ja4()}",
            $"JA4 raw            : {Ja4Raw()}",
        ]);
    }
}
