using System.Net;
using System.Net.Sockets;

namespace Router;

// RFC 6052 §2.1: an IPv4-embedded IPv6 address is a prefix followed by the four octets of an IPv4
// address, and the prefix length is one of six values. §2.2's figure is the layout: the octets begin
// where the prefix ends, and where that run would cross octet 8 - bits 64 to 71, which the figure keeps
// out of every embedding shorter than /96 - the run resumes behind it. Octet 8 is therefore zero in
// every embedded address whose prefix is shorter than /96, and an address carrying anything else there
// is not an embedding of anything, so reading one back is a refusal rather than a guess.
public static class Pref64
{
    public static readonly int[] PrefixLengths = { 32, 40, 48, 56, 64, 96 };

    public static bool TryParse(string text, out IPAddress? prefix, out int prefixLength)
    {
        prefix = null;
        prefixLength = 0;
        var slash = text.LastIndexOf('/');
        if (slash < 0) return false;
        if (!IPAddress.TryParse(text[..slash], out var address)) return false;
        if (address.AddressFamily != AddressFamily.InterNetworkV6) return false;
        if (!int.TryParse(text[(slash + 1)..], out prefixLength)) return false;
        if (Array.IndexOf(PrefixLengths, prefixLength) < 0) return false;

        // A prefix whose host bits are set names an address, not a prefix: embedding into it would put
        // the IPv4 octets over bits the configuration already gave a meaning of their own.
        var bytes = address.GetAddressBytes();
        for (var i = prefixLength; i < 128; i++)
            if (GetBit(bytes, i) != 0) return false;
        prefix = address;
        return true;
    }

    public static IPAddress Embed(IPAddress prefix, int prefixLength, IPAddress v4)
    {
        var bytes = prefix.GetAddressBytes();
        var v4Bytes = v4.GetAddressBytes();
        for (var i = 0; i < 32; i++)
            SetBit(bytes, DestinationBit(prefixLength, i), (v4Bytes[i / 8] >> (7 - i % 8)) & 1);
        return new IPAddress(bytes);
    }

    public static IPAddress? Extract(IPAddress prefix, int prefixLength, IPAddress v6)
    {
        if (v6.AddressFamily != AddressFamily.InterNetworkV6) return null;
        var bytes = v6.GetAddressBytes();
        var prefixBytes = prefix.GetAddressBytes();
        for (var i = 0; i < prefixLength; i++)
            if (GetBit(bytes, i) != GetBit(prefixBytes, i)) return null;
        if (prefixLength < 96)
        {
            for (var i = 64; i < 72; i++)
                if (GetBit(bytes, i) != 0) return null;
            for (var i = prefixLength + 40; i < 128; i++)
                if (GetBit(bytes, i) != 0) return null;
        }

        var v4 = new byte[4];
        for (var i = 0; i < 32; i++)
            if (GetBit(bytes, DestinationBit(prefixLength, i)) == 1)
                v4[i / 8] |= (byte)(0x80 >> (i % 8));
        return new IPAddress(v4);
    }

    private static int DestinationBit(int prefixLength, int i)
    {
        var dest = prefixLength + i;
        return prefixLength < 96 && dest >= 64 ? dest + 8 : dest;
    }

    private static int GetBit(byte[] bytes, int bit)
        => (bytes[bit / 8] >> (7 - bit % 8)) & 1;

    private static void SetBit(byte[] bytes, int bit, int value)
    {
        if (value == 1) bytes[bit / 8] |= (byte)(0x80 >> (bit % 8));
        else bytes[bit / 8] &= (byte)~(0x80 >> (bit % 8));
    }
}
