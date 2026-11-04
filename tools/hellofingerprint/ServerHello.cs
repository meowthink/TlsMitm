using System.Security.Cryptography;
using System.Text;

namespace HelloFingerprint;

/// <summary>
/// A TLS ServerHello read off the wire — the hello a client is answering when it is talking to us — plus
/// the two fingerprints computed from it. JA3S: MD5 over "TLSVersion,CipherSuite,Extensions" with the
/// version and the code points in decimal and the extensions in the order the hello carries them.
/// JA4S: the negotiated version, the count of extensions, the negotiated ALPN, the one cipher suite the
/// server chose, and a truncated SHA-256 of that same extension list.
/// Neither fingerprint sorts the list, and both hash it exactly as the server wrote it.
/// </summary>
public sealed class ServerHello
{
    public int HelloVersion { get; private init; }
    public int? SelectedVersion { get; private init; }
    public int CipherSuite { get; private init; }
    public int[] Extensions { get; private init; } = [];
    public byte[]? Alpn { get; private init; }

    /// RFC 8446 §4.1.3 sends a HelloRetryRequest as a server_hello (2) whose random is fixed to this value,
    /// the SHA-256 of "HelloRetryRequest". §4.1.4 keeps its extensions to what the client needs in order to
    /// send another hello, so they are not the session's selection.
    public static bool IsHelloRetryRequest(ReadOnlySpan<byte> record) =>
        record.Length >= 43 && record[0] == 0x16 && record[5] == 0x02 &&
        record.Slice(11, 32).SequenceEqual(HelloRetryRequestRandom);

    private static readonly byte[] HelloRetryRequestRandom = SHA256.HashData("HelloRetryRequest"u8);

    /// <summary>The span must start at a TLS record header (content type 22) and hold the whole hello.</summary>
    public static ServerHello? Parse(ReadOnlySpan<byte> record)
    {
        if (record.Length < 11 || record[0] != 0x16 || record[5] != 0x02) return null;
        if (IsHelloRetryRequest(record)) return null;
        var recordLength = Be16(record[3..]);
        if (recordLength > record.Length - 5) return null;
        record = record[..(5 + recordLength)];
        if (record.Length < 9) return null;

        // As in a ClientHello, the message length bounds this hello: a server may coalesce the next
        // handshake message into the same record.
        var message = (record[6] << 16) | (record[7] << 8) | record[8];
        if (message > record.Length - 9) return null;
        record = record[..(9 + message)];

        var p = 9;
        var helloVersion = Be16(record[p..]); p += 2 + 32;   // legacy version + random
        if (record.Length < p + 1) return null;
        p += 1 + record[p];                                   // legacy_session_id_echo
        if (record.Length < p + 2) return null;
        var cipher = Be16(record[p..]); p += 3;               // cipher suite + compression method

        // RFC 5246 §7.4.1.3 says the presence of a TLS 1.2 ServerHello's extensions "can be detected by
        // determining whether there are bytes following the compression_method field", so a hello may carry
        // no vector at all; the message length, already applied above, is what bounds the field.
        var extBytes = 0;
        if (record.Length > p)
        {
            if (record.Length < p + 2) return null;
            extBytes = Be16(record[p..]); p += 2;
            if (record.Length < p + extBytes) return null;
        }

        var types = new List<int>();
        int? selected = null;
        byte[]? alpn = null;
        var exts = record.Slice(p, extBytes);
        while (exts.Length >= 4)
        {
            var type = Be16(exts);
            var len = Be16(exts[2..]);
            if (exts.Length < 4 + len) return null;
            var body = exts.Slice(4, len);
            types.Add(type);
            if (type is 0x002b && len == 2)
                // RFC 8446 §4.2.1's union puts one selected_version, with no list length in front of it,
                // where a ClientHello carries a prefixed list.
                selected = Be16(body);
            else if (type is 0x0010 && len >= 3)
                // RFC 7301 §3.1: the server's ProtocolNameList holds exactly one ProtocolName.
                alpn = FirstProtocolName(body);
            exts = exts.Slice(4 + len);
        }
        if (!exts.IsEmpty) return null;

        return new ServerHello
        {
            HelloVersion = helloVersion,
            SelectedVersion = selected,
            CipherSuite = cipher,
            Extensions = [.. types],
            Alpn = alpn,
        };
    }

    private static byte[]? FirstProtocolName(ReadOnlySpan<byte> list)
    {
        var names = list[2..Math.Min(2 + Be16(list), list.Length)];
        if (names.IsEmpty || names[0] == 0 || names[0] > names.Length - 1) return null;
        return names[1..(1 + names[0])].ToArray();
    }

    private static int Be16(ReadOnlySpan<byte> s) => (s[0] << 8) | s[1];

    // ---- JA3S ----

    public string Ja3SString() => $"{HelloVersion},{CipherSuite},{string.Join('-', Extensions)}";

    public string Ja3S() => Ja4Format.Md5(Ja3SString());

    // ---- JA4S ----

    public string Ja4S() => $"{SectionA()}_{CipherSuite:x4}_{ExtensionHash()}";

    public string Ja4SRaw() => $"{SectionA()}_{CipherSuite:x4}_{Ja4Format.HexList(Extensions)}";

    // A server negotiating below TLS 1.3 MUST set ServerHello.version and MUST NOT send supported_versions,
    // and a TLS 1.3 server MUST send it (RFC 8446 §4.2.1), so exactly one of the two names the version here.
    private string SectionA() =>
        // t: every record this class reads was cut out of a TCP stream.
        "t" + Ja4Format.VersionCode(SelectedVersion ?? HelloVersion)
        + Math.Min(Extensions.Length, 99).ToString("00")
        + (Alpn is { Length: > 0 } name ? Ja4Format.AlpnCode(name) : "00");

    private string ExtensionHash() => Extensions.Length == 0
        ? "000000000000"
        : Ja4Format.Sha12(Ja4Format.HexList(Extensions));

    public override string ToString() => string.Join(Environment.NewLine,
    [
        $"legacy version     : 0x{HelloVersion:x4} ({HelloVersion})" +
            (SelectedVersion is int sv ? $" negotiated 0x{sv:x4}" : ""),
        $"cipher suite       : 0x{CipherSuite:x4} ({CipherSuite})",
        $"extensions ({Extensions.Length}) : {string.Join('-', Extensions)}  wire-order",
        $"alpn               : {(Alpn is { Length: > 0 } a ? Encoding.ASCII.GetString(a) : "(none)")}",
        "",
        $"JA3S string        : {Ja3SString()}",
        $"JA3S               : {Ja3S()}",
        $"JA4S               : {Ja4S()}",
        $"JA4S raw           : {Ja4SRaw()}",
    ]);
}
