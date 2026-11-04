using System.Security.Cryptography;
using System.Text;

namespace HelloFingerprint;

/// <summary>
/// The encodings the JA4 family shares between a client hello and a server hello: the version letters,
/// the ALPN code, and the lower-case hex text both hashes are taken over.
/// </summary>
internal static class Ja4Format
{
    public static string VersionCode(int v) => v switch
    {
        0x0304 => "13", 0x0303 => "12", 0x0302 => "11", 0x0301 => "10", 0x0300 => "s3",
        0x0002 => "s2", 0xfefd => "d2", 0xfefc => "d3", 0xfeff => "d1", _ => "00",
    };

    public static string AlpnCode(ReadOnlySpan<byte> name)
    {
        static bool Alnum(byte b) => b is >= 0x30 and <= 0x39 or >= 0x41 and <= 0x5a or >= 0x61 and <= 0x7a;
        if (Alnum(name[0]) && Alnum(name[^1])) return $"{(char)name[0]}{(char)name[^1]}";
        var hex = Convert.ToHexString(name).ToLowerInvariant();
        return $"{hex[0]}{hex[^1]}";
    }

    public static string HexList(int[] values) => string.Join(',', values.Select(v => v.ToString("x4")));
    public static string Md5(string text) => Hex(MD5.HashData(Encoding.ASCII.GetBytes(text)));
    public static string Sha12(string text) => Hex(SHA256.HashData(Encoding.ASCII.GetBytes(text)))[..12];

    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();
}
