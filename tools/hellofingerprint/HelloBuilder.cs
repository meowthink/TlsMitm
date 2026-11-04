using System.Text;

namespace HelloFingerprint;

/// <summary>
/// Hand-assembles a ClientHello for the parser check. Only what that check needs is here: a hello whose
/// fields are known octet for octet, so a decoder bug shows up as a wrong field rather than a wrong hash.
/// </summary>
public static class HelloBuilder
{
    public static byte[] BuildHello(int version, int[] ciphers, params (int Type, byte[] Body)[] extensions)
    {
        var exts = new List<byte>();
        foreach (var (type, body) in extensions)
        {
            U16(exts, type); U16(exts, body.Length); exts.AddRange(body);
        }

        var hello = new List<byte>();
        U16(hello, version);
        hello.AddRange(new byte[32]);                     // random
        hello.Add(0);                                     // no session id
        U16(hello, ciphers.Length * 2);                   // the vector counts the suites, not itself
        foreach (var c in ciphers) U16(hello, c);
        hello.Add(1); hello.Add(0);                       // one compression method: null
        U16(hello, exts.Count);
        hello.AddRange(exts);

        var handshake = new List<byte> { 0x01 };          // handshake type: client_hello
        var length = hello.Count;
        handshake.Add((byte)(length >> 16)); handshake.Add((byte)(length >> 8)); handshake.Add((byte)length);
        handshake.AddRange(hello);

        var record = new List<byte> { 0x16, 0x03, 0x01 }; // content type handshake, legacy record version
        U16(record, handshake.Count);
        record.AddRange(handshake);
        return [.. record];
    }

    /// <summary>ServerNameList with one host_name entry (RFC 6066 §3).</summary>
    public static byte[] Sni(string host)
    {
        var name = Ascii.GetBytes(host);
        var list = new List<byte> { 0 };                  // NameType host_name = 0
        U16(list, name.Length);
        list.AddRange(name);
        var body = new List<byte>();
        U16(body, list.Count);
        body.AddRange(list);
        return [.. body];
    }

    /// <summary>NamedGroupList, which supported_groups and signature_algorithms both use.</summary>
    public static byte[] Pairs16(int[] values)
    {
        var inner = new List<byte>();
        foreach (var v in values) U16(inner, v);
        var body = new List<byte>();
        U16(body, inner.Count);
        body.AddRange(inner);
        return [.. body];
    }

    public static byte[] Groups(int[] values) => Pairs16(values);
    public static byte[] SigAlgs(int[] values) => Pairs16(values);

    /// <summary>ECPointFormatList: one length byte, then one octet per format.</summary>
    public static byte[] PointFormats(int[] values)
    {
        var body = new List<byte> { (byte)values.Length };
        body.AddRange(values.Select(v => (byte)v));
        return [.. body];
    }

    /// <summary>SupportedVersions: one length byte, then two octets per version (RFC 8446 §4.2.1).</summary>
    public static byte[] SupportedVersions(int[] values)
    {
        var body = new List<byte> { (byte)(values.Length * 2) };
        foreach (var v in values) U16(body, v);
        return [.. body];
    }

    /// <summary>ProtocolIdList: each protocol is a length byte plus its ASCII id (RFC 7301 §4).</summary>
    public static byte[] Alpn(string[] protocols)
    {
        var inner = new List<byte>();
        foreach (var p in protocols)
        {
            var bytes = Ascii.GetBytes(p);
            inner.Add((byte)bytes.Length);
            inner.AddRange(bytes);
        }
        var body = new List<byte>();
        U16(body, inner.Count);
        body.AddRange(inner);
        return [.. body];
    }

    private static readonly Encoding Ascii = System.Text.Encoding.ASCII;

    private static void U16(List<byte> list, int value)
    {
        list.Add((byte)(value >> 8));
        list.Add((byte)value);
    }
}
