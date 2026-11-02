using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using TlsMitm;

namespace Router;

// RFC 7915's IP/ICMP translation: take the header one family off a packet and put the other family's on, with
// the fields §4.1 and §5.1 pair off one by one, the ICMP types and codes §4.2 and §5.2 map, and the transport
// checksum §4.5 and §5.5 recompute when the address mapping is not checksum neutral. It is the packet-handling
// half of what RFC 6146's stateful translator does; the state that decides which addresses a flow's pair came
// from is that document's, and this file holds none, so both directions here are functions of the packet in
// front of them and of the mapping their caller hands over.
//
// Three things a translator owes its configuration stay outside this file, and each shows up as an argument the
// caller supplies: the Fragment Identification generator §5.1 names, the two next-hop MTUs that the Packet Too
// Big formulas of §4.2 and §5.2 read, and the §4.5 choice between dropping and computing a checksum-less UDP
// packet, which is taken as computing it. Fragmenting is outside too: §4 asks that "the translator MUST NOT
// include the Fragment Header for the non-fragmented IPv6 packets" while §4.1 asks that an over-large IPv4
// datagram be fragmented so its IPv6 packets fit the minimum MTU, and §5.1.1 that an over-large translated IPv4
// datagram be fragmented by the translator - each of which means emitting several packets where one came in,
// which is a decision about a path rather than about a packet.
public static class Siit
{
    public const int Ipv4HeaderLength = 20;

    // RFC 7915 §5: "An IPv6 link has to have an MTU of 1280 bytes or greater", and §5's Don't Fragment rule for
    // a translated IPv4 datagram turns on how it compares to that figure minus its own header.
    public const int MinimumIpv6Mtu = 1280;
    public const int Ipv4DfThreshold = MinimumIpv6Mtu - Ipv4HeaderLength;

    private const byte NextHopByHop = 0;
    private const byte NextRouting = 43;
    private const byte NextFragment = 44;
    private const byte NextEsp = 50;
    private const byte NextAh = 51;
    private const byte NextNoNext = 59;
    private const byte NextDestination = 60;
    private const byte ProtocolIcmpv4 = 1;
    private const byte ProtocolTcp = 6;
    private const byte ProtocolUdp = 17;
    private const byte Icmpv6 = 58;

    /// The two path figures §4.2's and §5.2's Packet Too Big formulas read, which belong to the translator's
    /// configuration and not to a packet. <see cref="Unknown"/> stands where a translator knows only the family
    /// it is sending to, and the formula then chooses between the message's own figure and the other side's.
    public readonly record struct PathMtu(int Ipv4NextHop, int Ipv6NextHop)
    {
        public static readonly PathMtu Unknown = new(int.MaxValue, int.MaxValue);
    }

    /// The address mapping §6 asks a translator to have: RFC 6052's stateless one by default, RFC 7757's
    /// explicit one or RFC 6146's tables otherwise. It is handed the pair together because §4.3's and §5.3's
    /// "The translation of the inner IP header can be done by invoking the function that translated the outer
    /// IP headers" gives the header quoted inside an error message the same function, and a table that answers
    /// for one leg of a flow answers for both.
    public delegate bool AddressMap(IPAddress source, IPAddress destination,
        out IPAddress? mappedSource, out IPAddress? mappedDestination);

    /// §6's "The translator MUST support the stateless address mapping algorithm defined in [RFC6052], which is
    /// the default behavior", read in whichever direction the packet is going: an IPv4 address becomes its
    /// embedding in the prefix, a member of the prefix becomes the IPv4 address embedded in it.
    public static AddressMap FromPrefix(Pref64Config prefix) =>
        (IPAddress source, IPAddress destination, out IPAddress? mappedSource,
            out IPAddress? mappedDestination) =>
        {
            mappedSource = MapOne(prefix, source);
            mappedDestination = MapOne(prefix, destination);
            return mappedSource is not null && mappedDestination is not null;
        };

    /// §5.6's and §4.6's "the destination address is reachable by a more specific route without translation"
    /// question, which is a routing one: this says only whether the address is one that represents a host in the
    /// other domain.
    public static bool IsTranslatable(IPAddress destination, Pref64Config prefix) =>
        Pref64.Extract(prefix.Prefix, prefix.PrefixLength, destination) is not null;

    /// RFC 7915 §5's IPv6-to-IPv4 translation. `identification` is what §5.1's "Set according to a Fragment
    /// Identification generator at the translator" hands to the caller, and a packet that came in fragmented
    /// ignores it, taking its Identification from the Fragment Header as §5.1.1 says.
    public static bool TryV6ToV4(ReadOnlySpan<byte> packet, AddressMap map, ushort identification, PathMtu path,
        out byte[]? translated, out string why) =>
        Translate64(packet, map, identification, path, false, out translated, out why);

    /// RFC 7915 §4's IPv4-to-IPv6 translation, including the Fragment Header §4.1's fragment case adds over a
    /// packet that came in fragmented.
    public static bool TryV4ToV6(ReadOnlySpan<byte> packet, AddressMap map, PathMtu path,
        out byte[]? translated, out string why) =>
        Translate46(packet, map, path, false, out translated, out why);

    // --- the mapping, and the two ICMP tables -----------------------------------------------------------------------------

    private static IPAddress? MapOne(Pref64Config prefix, IPAddress address) => address.AddressFamily switch
    {
        AddressFamily.InterNetworkV6 => Pref64.Extract(prefix.Prefix, prefix.PrefixLength, address),
        AddressFamily.InterNetwork => Pref64.Embed(prefix.Prefix, prefix.PrefixLength, address),
        _ => null
    };

    // One row of §4.2's or §5.2's table, in the shape the writer needs: the Type and Code the translated message
    // carries, whether a packet is quoted inside it - §4.2's and §5.2's words are "for ICMPv4 error messages,
    // the included IP header also MUST be translated" - the pointer Figure 3 and Figure 6 give, the MTU the two
    // Packet Too Big formulas exchange, and how many bytes of the quoted region RFC 4884's length attribute
    // guarantees.
    private readonly record struct Shape(byte Type, byte Code, bool Error, int Pointer, uint Mtu, bool HasMtu,
        int GuaranteedBytes);

    // §5.2's table, read from the message's own Type and Code.
    private static bool TryShape64(ReadOnlySpan<byte> message, PathMtu path, out Shape shape, out string why)
    {
        shape = default;
        why = "";
        var type = message[0];
        var code = message[1];
        // RFC 4884 §4.4 and §4.5 give an ICMPv6 Destination Unreachable and Time Exceeded a length attribute in
        // the fifth octet counting 64-bit words; the other three messages §4.6 lists as extendable are the ICMPv4
        // ones, and of the remaining two §4.6 says "Extensions were not defined for the ICMPv6 'Packet Too Big'
        // and 'Parameter Problem' messages because these messages lack space for a length attribute".
        var guaranteed = type is 1 or 3 ? message[4] * 8 : 0;

        switch (type)
        {
            // §5.2: "Echo Request and Echo Reply (Type 128 and 129): Adjust the Type values to 8 and 0,
            // respectively, and adjust the ICMP checksum both to take the type change into account and to
            // exclude the ICMPv6 pseudo-header."
            case 128: shape = new Shape(8, 0, false, -1, 0, false, 0); return true;
            case 129: shape = new Shape(0, 0, false, -1, 0, false, 0); return true;

            // §5.2: "MLD Multicast Listener Query/Report/Done (Type 130, 131, 132): Single-hop message. Silently
            // drop." and "Neighbor Discover messages (Type 133 through 137): Single-hop message. Silently drop."
            case >= 130 and <= 137:
                why = $"ICMPv6 type {type} is one of §5.2's single-hop messages, which the table silently drops";
                return false;

            // §5.2: "Destination Unreachable (Type 1) Set the Type to 3", then its code list.
            case 1:
                var unreachable = code switch { 0 => 1, 1 => 10, 2 => 1, 3 => 1, 4 => 3, _ => -1 };
                if (unreachable < 0)
                {
                    why = $"§5.2's Destination Unreachable list ends in 'Other Code values: Silently drop', and code {code} is past it";
                    return false;
                }
                shape = new Shape(3, (byte)unreachable, true, -1, 0, false, guaranteed);
                return true;

            // §5.2: "Packet Too Big (Type 2): Translate to an ICMPv4 Destination Unreachable (Type 3) with Code
            // 4 ... The MTU field MUST be adjusted for the difference between the IPv4 and IPv6 header sizes,
            // taking into account whether or not the packet in error includes a Fragment Header, i.e.,
            // minimum((MTU value in the Packet Too Big Message)-20, MTU_of_IPv4_nexthop,
            // (MTU_of_IPv6_nexthop)-20)."
            case 2:
                var reported = (long)BinaryPrimitives.ReadUInt32BigEndian(message.Slice(4, 4));
                var narrowed = Math.Min(Math.Max(reported - 20, 0),
                    Math.Min((long)path.Ipv4NextHop, path.Ipv6NextHop >= 20 ? (long)path.Ipv6NextHop - 20 : 0));
                shape = new Shape(3, 4, true, -1, (uint)narrowed, true, 0);
                return true;

            // §5.2: "Time Exceeded (Type 3): Set the Type to 11 ... The Code is unchanged."
            case 3: shape = new Shape(11, code, true, -1, 0, false, guaranteed); return true;

            case 4:
                switch (code)
                {
                    // §5.2: "Code 0 (Erroneous header field encountered): Set to Type 12, Code 0, and update the
                    // pointer as defined in Figure 6. (If the Original IPv6 Pointer Value is not listed or the
                    // Translated IPv4 Pointer Value is listed as 'n/a', silently drop the packet.)"
                    case 0:
                        if (!TryPointer6(message[4], out var pointer, out why)) return false;
                        shape = new Shape(12, 0, true, pointer, 0, false, 0);
                        return true;
                    // §5.2: "Code 1 (Unrecognized Next Header type encountered): Translate this to an ICMPv4
                    // protocol unreachable (Type 3, Code 2)."
                    case 1: shape = new Shape(3, 2, true, -1, 0, false, 0); return true;
                    // §5.2: "Code 2 (Unrecognized IPv6 option encountered): Silently drop."
                    default:
                        why = $"§5.2's Parameter Problem list silently drops code {code}";
                        return false;
                }

            default:
                why = $"ICMPv6 type {type} is not a row of §5.2's table, which ends in 'Unknown error messages: Silently drop'";
                return false;
        }
    }

    // §4.2's table. `quotedTotalLength` is the Total Length an embedded header carries, which §4.2 reads when a
    // Fragmentation Needed message's own MTU figure is zero.
    private static bool TryShape46(ReadOnlySpan<byte> message, PathMtu path, ushort quotedTotalLength,
        out Shape shape, out string why)
    {
        shape = default;
        why = "";
        var type = message[0];
        var code = message[1];
        // RFC 4884 §4.1, §4.2 and §4.3 give an ICMPv4 Destination Unreachable, Time Exceeded and Parameter Problem
        // a length attribute counting 32-bit words of the quoted datagram, and §3 puts it in one place for all
        // three: "Because the sixth octet of each of the impacted ICMPv4 messages was reserved for future use,
        // this octet was selected as the location of the length attribute in ICMPv4." Parameter Problem's Pointer
        // keeps the fifth octet RFC 792 gave it.
        var guaranteed = type is 3 or 11 or 12 ? message[5] * 4 : 0;

        switch (type)
        {
            // §4.2: "Echo and Echo Reply (Type 8 and Type 0): Adjust the Type values to 128 and 129,
            // respectively, and adjust the ICMP checksum both to take the type change into account and to
            // include the ICMPv6 pseudo-header."
            case 8: shape = new Shape(128, 0, false, -1, 0, false, 0); return true;
            case 0: shape = new Shape(129, 0, false, -1, 0, false, 0); return true;

            // §4.2: "Destination Unreachable (Type 3): Translate the Code as described below, set the Type to 1".
            case 3:
                switch (code)
                {
                    // §4.2: "Code 0, 1 (Net Unreachable, Host Unreachable): Set the Code to 0 (No route to
                    // destination)." - and the same for Code 5, Code 6, 7, 8, and Code 11, 12.
                    case 0 or 1 or 5 or 6 or 7 or 8 or 11 or 12:
                        shape = new Shape(1, 0, true, -1, 0, false, guaranteed);
                        return true;
                    // §4.2: "Code 2 (Protocol Unreachable): Translate to an ICMPv6 Parameter Problem (Type 4,
                    // Code 1) and make the Pointer point to the IPv6 Next Header field." RFC 8200 §3 puts that
                    // field at the seventh octet of the base header.
                    case 2: shape = new Shape(4, 1, true, 6, 0, false, 0); return true;
                    // §4.2: "Code 3 (Port Unreachable): Set the Code to 4 (Port unreachable)."
                    case 3: shape = new Shape(1, 4, true, -1, 0, false, guaranteed); return true;
                    case 4:
                        shape = new Shape(2, 0, true, -1, ReportedMtu4(message, path, quotedTotalLength), true, 0);
                        return true;
                    // §4.2: "Code 9, 10 ... Set the Code to 1", "Code 13 ... Set the Code to 1", "Code 15 ... Set
                    // the Code to 1".
                    case 9 or 10 or 13 or 15:
                        shape = new Shape(1, 1, true, -1, 0, false, guaranteed);
                        return true;
                    // §4.2: "Code 14 (Host Precedence Violation): Silently drop." and "Other Code values:
                    // Silently drop."
                    default:
                        why = $"§4.2's Destination Unreachable list silently drops code {code}";
                        return false;
                }

            // §4.2: "Time Exceeded (Type 11): Set the Type to 3 ... The Code is unchanged."
            case 11: shape = new Shape(3, code, true, -1, 0, false, guaranteed); return true;

            case 12:
                // §4.2: "Parameter Problem (Type 12): Set the Type to 4", and Code 0 and Code 2 each "Set the
                // Code to 0 (Erroneous header field encountered) and update the pointer as defined in Figure 3.
                // (If the Original IPv4 Pointer Value is not listed or the Translated IPv6 Pointer Value is
                // listed as 'n/a', silently drop the packet.)"
                if (code is not (0 or 2))
                {
                    why = $"§4.2's Parameter Problem list silently drops code {code}";
                    return false;
                }
                if (!TryPointer4(message[4], out var pointer, out why)) return false;
                shape = new Shape(4, 0, true, pointer, 0, false, 0);
                return true;

            // §4.2 silently drops the rest of them by name: "Information Request/Reply (Type 15 and Type 16)",
            // "Timestamp and Timestamp Reply (Type 13 and Type 14)", "Address Mask Request/Reply (Type 17 and
            // Type 18)", "ICMP Router Advertisement (Type 9)", "ICMP Router Solicitation (Type 10)", "Redirect
            // (Type 5)", "Alternative Host Address (Type 6)", "Source Quench (Type 4)" and "Unknown ICMPv4
            // types", and it asks the same for IGMP, whose messages are "single-hop messages ... and SHOULD be
            // silently dropped by the translator".
            default:
                why = $"ICMPv4 type {type} is one §4.2 silently drops";
                return false;
        }
    }

    // The discriminator §4.3's and §5.3's "drop the packet if it contains more embedded headers" needs, taken
    // from the two tables themselves: their rows mark which messages are errors, and an error inside the quote is
    // the one that would carry a further embedded IP header. RFC 6146 §3.4 draws the same line twice over, and its
    // third bullet is why this reads the Type instead of refusing every embedded ICMP message - "If the incoming IP
    // packet contains a complete (un-fragmented) ICMP error message containing an ICMP Query message" is a packet
    // to process, and the Echo Request a peer quotes back when it answers a translator's own query is that case. A
    // quote whose message no table describes fails here for the same reason the tables drop it anywhere else.
    private static bool QuoteIsError4(ReadOnlySpan<byte> quote, V4Header head, PathMtu path) =>
        quote.Length >= head.Transport + 8 &&
        (!TryShape46(quote[head.Transport..], path, 0, out var shape, out _) || shape.Error);

    private static bool QuoteIsError6(ReadOnlySpan<byte> quote, V6Header head, PathMtu path) =>
        quote.Length >= head.Transport + 8 &&
        (!TryShape64(quote[head.Transport..], path, out var shape, out _) || shape.Error);

    // §4.2: "Code 4 (Fragmentation Needed and DF was Set): Translate to an ICMPv6 Packet Too Big message (Type
    // 2) with Code set to 0. The MTU field MUST be adjusted for the difference between the IPv4 and IPv6 header
    // sizes, but MUST NOT be set to a value smaller than the minimum IPv6 MTU (1280 bytes). That is, it should
    // be set to maximum(1280, minimum((MTU value in the Packet Too Big Message) + 20, MTU_of_IPv6_nexthop,
    // (MTU_of_IPv4_nexthop) + 20))."
    private static uint ReportedMtu4(ReadOnlySpan<byte> message, PathMtu path, ushort quotedTotalLength)
    {
        var reported = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(6, 2));
        // The same paragraph continues: "Note that if the IPv4 router set the MTU field to zero, i.e., the
        // router does not implement [RFC1191], then the translator MUST use the plateau values specified in
        // [RFC1191] ... (Use the greatest plateau value that is less than the returned Total Length field, but
        // that is larger than or equal to 1280.)" RFC 1191 §5's Note about 4.2BSD routers asks for its correction
        // only when the returned Total Length is not less than the receiver's current PMTU estimate, and a file
        // that holds no estimate reads the field as it arrived.
        if (reported == 0) return Plateau(quotedTotalLength);
        return (uint)Math.Max(MinimumIpv6Mtu,
            Math.Min((long)reported + 20, Math.Min((long)path.Ipv6NextHop, (long)path.Ipv4NextHop + 20)));
    }

    // RFC 1191 §7's Table 7-1, kept down to the plateaus at or above the figure §4.2's sentence floors the answer
    // at, and ordered so that the first one below the quoted Total Length is also the greatest.
    private static readonly int[] Plateaus = [65535, 32000, 17914, 8166, 4352, 2002, 1492];

    private static uint Plateau(ushort totalLength)
    {
        foreach (var plateau in Plateaus)
            if (plateau < totalLength) return (uint)plateau;
        return MinimumIpv6Mtu;
    }

    // Figure 6, "Pointer Value for Translating from IPv6 to IPv4": 0→0, 1→1, 4 and 5→2, 6→9, 7→8, 8 through
    // 23→12, 24 through 39→16. Flow Label's 2 and 3 are the rows that read n/a, and an octet past 39 is not
    // listed at all, which §5.2 answers by dropping the message.
    private static bool TryPointer6(byte pointer, out int translated, out string why)
    {
        translated = pointer switch
        {
            <= 1 => pointer,
            >= 4 and <= 5 => 2,
            6 => 9,
            7 => 8,
            >= 8 and <= 23 => 12,
            >= 24 and <= 39 => 16,
            _ => -1
        };
        why = translated < 0 ? $"Figure 6 lists no IPv4 field for a pointer at octet {pointer}" : "";
        return translated >= 0;
    }

    // Figure 3, "Pointer Value for Translating from IPv4 to IPv6": 0→0, 1→1, 2 and 3→4, 8→7, 9→6, 12 through
    // 15→8, 16 through 19→24. Identification, Flags/Fragment Offset, Fragment Offset and Header Checksum have no
    // IPv6 counterpart, and §4.2 drops a message that points at one of them.
    private static bool TryPointer4(byte pointer, out int translated, out string why)
    {
        translated = pointer switch
        {
            <= 1 => pointer,
            2 or 3 => 4,
            8 => 7,
            9 => 6,
            >= 12 and <= 15 => 8,
            >= 16 and <= 19 => 24,
            _ => -1
        };
        why = translated < 0 ? $"Figure 3 lists no IPv6 field for a pointer at octet {pointer}" : "";
        return translated >= 0;
    }

    // --- IPv6 to IPv4 -------------------------------------------------------------------------------------

    // `asQuote` is §5.3's case: the header inside an error message, which is translated by this same function
    // and which the RFC's own figure labels "Partial Transport-Layer Header". Three rules below are for the
    // ordinary packet only: the one Hop Limit decrement §5.1 asks a forwarding translator for (§5.3's words:
    // "except that the TTL/Hop Limit value of the inner IPv4/IPv6 packet are not decremented"), the illegal
    // source check, which §4.1 excepts for the messages that carry a quote because "when translating ICMPv4
    // Error Messages into ICMPv6, the 'illegal' source address will be translated for the purpose of trouble
    // shooting", and the transport checksum, which cannot be recomputed over a header whose message is not all
    // on hand.
    private static bool Translate64(ReadOnlySpan<byte> packet, AddressMap map, ushort identification, PathMtu path,
        bool asQuote, out byte[]? translated, out string why)
    {
        translated = null;
        why = "";
        if (!TryReadV6(packet, asQuote, out var head, out why)) return false;

        var source6 = new IPAddress(packet.Slice(8, 16).ToArray());
        var destination6 = new IPAddress(packet.Slice(24, 16).ToArray());
        if (!asQuote && head.Protocol != Icmpv6 && IsIllegal(source6, out why)) return false;
        if (!map(source6, destination6, out var source, out var destination) ||
            source is null || destination is null || source.AddressFamily != AddressFamily.InterNetwork)
        {
            why = $"the mapping in use does not reach both {source6} and {destination6}";
            return false;
        }

        var hopLimit = packet[7];
        if (!asQuote)
        {
            // §5.1: "as part of decrementing the TTL or Hop Limit, the translator (as any router) MUST check for
            // zero and send the ICMPv4 'TTL Exceeded' or ICMPv6 'Hop Limit Exceeded' error". The error is the
            // caller's to send; this is the reason the packet stopped.
            if (hopLimit <= 1)
            {
                why = $"the Hop Limit is {hopLimit}, so §5.1's zero check stops the packet here";
                return false;
            }
            hopLimit--;
        }

        var shape = default(Shape);
        var message = head.Protocol == Icmpv6 ? packet[head.Transport..head.DatagramEnd] : ReadOnlySpan<byte>.Empty;
        if (head.Protocol == Icmpv6)
        {
            // §3: "Fragmented ICMP/ICMPv6 packets will not be translated by IP/ICMP translators", and a fragment
            // other than the first has no Type octet for the table to read anyway.
            if (head.Fragmented)
            {
                why = "the ICMPv6 message sits behind a Fragment Header, and §3 says a fragmented ICMP packet is not translated";
                return false;
            }
            if (message.Length < 8)
            {
                why = $"the ICMPv6 message at {head.Transport} is {message.Length} octets, short of the 8 its Type, Code and checksum need";
                return false;
            }
            if (!TryShape64(message, path, out shape, out why)) return false;
        }

        ReadOnlySpan<byte> region = [];
        ReadOnlySpan<byte> embedded = [];
        ReadOnlySpan<byte> tail = [];
        byte[]? quoted = null;
        if (shape.Error)
        {
            region = message[8..];
            SplitQuote(region, shape.GuaranteedBytes, true, out embedded, out tail);
            if (!TryReadV6(embedded, true, out var embeddedHead, out _))
            {
                why = "the packet quoted in the ICMPv6 error is not an IPv6 packet this translation can read";
                return false;
            }
            if (embeddedHead.Protocol == Icmpv6 && QuoteIsError6(embedded, embeddedHead, path))
            {
                why = "§5.3 stops at the first embedded header and drops \"if it contains more embedded headers\", " +
                      "and the quoted ICMPv6 message is one of §5.2's error rows or one that table does not name";
                return false;
            }
            if (!Translate64(embedded, map, identification, path, true, out quoted, out why)) return false;
        }

        var header = TransportHeaderLength(head.Protocol);
        var whole = head.FragmentOffset == 0 && head.Transport + header <= head.DatagramEnd;
        if (!asQuote && whole && head.Protocol == ProtocolUdp &&
            BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(head.Transport + 6, 2)) == 0)
        {
            // RFC 8200 §8.1: "IPv6 receivers must discard UDP packets containing a zero checksum and should log
            // the error." This file is the receiver of the packet it is handed.
            why = "the UDP checksum is zero, which RFC 8200 §8.1 makes a receiver discard";
            return false;
        }

        byte[] body;
        if (head.Protocol == Icmpv6)
            body = BuildIcmp(false, shape, quoted, embedded, tail, message, source, destination);
        else if (!asQuote && whole && head.Protocol is ProtocolTcp or ProtocolUdp)
            body = TranslateTransport64(packet[head.Transport..head.DatagramEnd], head, source, destination,
                source6, destination6);
        else
            body = packet[head.Transport..head.DatagramEnd].ToArray();

        if (Ipv4HeaderLength + body.Length > ushort.MaxValue)
        {
            why = $"the {body.Length}-octet body leaves no 16-bit Total Length for RFC 791 §3.1's header to carry";
            return false;
        }

        var result = new byte[Ipv4HeaderLength + body.Length];
        Write4Header(result, packet, head, source, destination, identification, body.Length, hopLimit);
        body.CopyTo(result.AsSpan(Ipv4HeaderLength));
        translated = result;
        return true;
    }

    // RFC 8200 §3's base header plus the two Fragment Header fields §5.1.1 copies into the IPv4 header.
    public readonly record struct V6Header(int Transport, byte Protocol, int DatagramEnd, bool Fragmented,
        int FragmentOffset, bool MoreFragments, uint Identification);

    // The chain §5.1's "Protocol" step walks: "The IPv6 headers HOPOPT (0), IPv6-Route (43), and IPv6-Opts (60)
    // are skipped over during processing as they have no meaning in IPv4. For the first 'next header' that does
    // not match one of the cases above, its Next Header value (which contains the transport protocol number) is
    // copied to the protocol field in the IPv4 header. This means that all transport protocols are translated."
    // The Fragment Header is §5.1.1's case, and an Authentication Header is one of the "first next header"
    // cases, which §5.1's Note accepts will "fail at the receiver ... when translated (e.g., IPsec
    // Authentication Header (51))".
    // `truncated` is a quoted header's case, where §4.3's and §5.3's figures show only a partial transport
    // header and where the length fields say more than the message carries.
    public static bool TryReadV6(ReadOnlySpan<byte> packet, bool truncated, out V6Header head, out string why)
    {
        head = default;
        why = "";
        if (packet.Length < Ipv6Chain.HeaderLength)
        {
            why = $"an IPv6 header is {Ipv6Chain.HeaderLength} octets and only {packet.Length} are here";
            return false;
        }
        if (packet[0] >> 4 != 6)
        {
            why = $"the version field says {packet[0] >> 4}, not 6";
            return false;
        }

        // RFC 8200 §3: Payload Length is "Length of the IPv6 payload, i.e., the rest of the packet following this
        // IPv6 header, in octets", extension headers included, so octets past it are padding rather than this
        // datagram, and a buffer shorter than it is a datagram that did not all arrive.
        var declared = Ipv6Chain.HeaderLength + BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(4, 2));
        if (declared > packet.Length && !truncated)
        {
            why = $"payload length {declared} claims more than the {packet.Length} octets here";
            return false;
        }
        var end = Math.Min(declared, packet.Length);

        var offset = Ipv6Chain.HeaderLength;
        var next = packet[6];
        var fragmented = false;
        var fragmentOffset = 0;
        var moreFragments = false;
        uint fragmentId = 0;
        var hops = 0;
        while (next is NextHopByHop or NextRouting or NextDestination or NextFragment)
        {
            if (offset + 8 > end || ++hops > 8)
            {
                why = $"the extension header at {offset} runs past the {end} octets the datagram is";
                return false;
            }
            var following = packet[offset];
            // RFC 8200 §4.3's Hdr Ext Len is "Length of the Hop-by-Hop Options header in 8-octet units, not
            // including the first 8 octets", and §4.4 and §4.6 give the routing header and a second destination
            // options header the same figure.
            var length = (packet[offset + 1] + 1) * 8;
            if (length < 8 || offset + length > end)
            {
                why = $"the extension header at {offset} declares {length} octets inside {end - offset}";
                return false;
            }

            if (next == NextRouting && packet[offset + 3] != 0)
            {
                // §5.1: "If a Routing header with a non-zero Segments Left field is present, then the packet MUST
                // NOT be translated, and an ICMPv6 'parameter problem/erroneous header field encountered' (Type
                // 4, Code 0) error message, with the Pointer field indicating the first byte of the Segments Left
                // field, SHOULD be returned to the sender." RFC 8200 §4.4.1 puts Segments Left at the fourth octet
                // of the header, which is the octet this packet's pointer would name.
                why = $"§5.1 refuses a routing header with {packet[offset + 3]} segments left, and asks for a Parameter Problem pointing at octet {offset + 3}";
                return false;
            }

            if (next == NextFragment)
            {
                // RFC 8200 §4.5's header: Next Header, Reserved, the 13-bit Fragment Offset with two reserved bits
                // and the M flag after it, and a 32-bit Identification. §5.1.1's rules take all three into the IPv4
                // header, whose Flags and Fragment Offset word lays the same 13-bit offset out the same way.
                fragmented = true;
                var fragmentWord = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(offset + 2, 2));
                fragmentOffset = fragmentWord >> 3;
                moreFragments = (fragmentWord & 0x01) != 0;
                fragmentId = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(offset + 4, 4));
                // §5.1.1: "If the Next Header field of the Fragment Header is an extension header (except ESP,
                // but including the Authentication Header (AH)), then the packet SHOULD be dropped and logged."
                if (following != NextEsp && IsExtensionHeader(following))
                {
                    why = $"§5.1.1 drops a packet whose Fragment Header names extension header {following} behind it";
                    return false;
                }
                offset += length;
                next = following;
                break;
            }

            offset += length;
            next = following;
        }

        if (next == NextNoNext)
        {
            // RFC 8200 §4.7: the value 59 "indicates that there is nothing following that header", so there is no
            // datagram to hand over.
            why = "a No Next Header (59) leaves nothing behind it to translate";
            return false;
        }

        if (!truncated && !fragmented)
        {
            // A whole datagram has its transport header in it, and §8.1's pseudo-header is computed from what
            // follows it; a fragment other than the first has no header there at all.
            var length = TransportHeaderLength(next);
            if (length > 0 && offset + length > end)
            {
                why = $"the transport header at {offset} is not all inside the datagram's {end} octets";
                return false;
            }
        }

        head = new V6Header(offset, next, end, fragmented, fragmentOffset, moreFragments, fragmentId);
        return true;
    }

    private static bool IsExtensionHeader(byte next) =>
        next is NextHopByHop or NextRouting or NextFragment or NextAh or NextDestination;

    // The part of a transport header a checksum field sits in: RFC 793 §3.1's 20 octets of TCP, RFC 768's 8 of
    // UDP, and the 8 RFC 792 §1.1 and RFC 4443 §2.4 give an ICMP message before its data.
    private static int TransportHeaderLength(byte protocol) => protocol switch
    {
        ProtocolTcp => 20,
        ProtocolUdp or Icmpv6 or ProtocolIcmpv4 => 8,
        _ => 0
    };

    // §5.1's field list, in the order RFC 791 §3.1's header puts them.
    private static void Write4Header(byte[] result, ReadOnlySpan<byte> packet, V6Header head, IPAddress source,
        IPAddress destination, ushort identification, int bodyLength, byte hopLimit)
    {
        result[0] = 0x45; // Version 4, IHL 5: this translation puts no IPv4 option in the header.
        // §5.1: "Type of Service (TOS) Octet: By default, copied from the IPv6 Traffic Class". RFC 8200 §3 splits
        // that class across the first two octets, four bits after the version and four before the flow label.
        result[1] = (byte)(((packet[0] & 0x0F) << 4) | (packet[1] >> 4));
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(2), (ushort)(Ipv4HeaderLength + bodyLength));
        // §5.1.1: "Identification: Copied from the low-order 16 bits in the Identification field in the Fragment
        // Header." §5.1's own row is "Set according to a Fragment Identification generator at the translator".
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4),
            (ushort)(head.Fragmented ? head.Identification & 0xFFFF : identification));
        // §5.1.1: "The IPv4 More Fragments (MF) flag is copied from the M flag in the IPv6 Fragment Header. The
        // IPv4 Don't Fragment (DF) flag is cleared (set to zero), allowing this packet to be further fragmented
        // by IPv4 routers." For a whole datagram it is §5's rule: "When the resulting IPv4 packet is smaller than
        // or equal to 1260 bytes, the translator MUST send the packet with a cleared Don't Fragment bit.
        // Otherwise, the packet MUST be sent with the Don't Fragment bit set."
        var flags = head.Fragmented
            ? (head.MoreFragments ? 0x2000 : 0) | (head.FragmentOffset & 0x1FFF)
            : Ipv4HeaderLength + bodyLength > Ipv4DfThreshold ? 0x4000 : 0;
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(6), (ushort)flags);
        result[8] = hopLimit;
        // §5.1: "ICMPv6 (58) is changed to ICMPv4 (1)", and every other header the walk stopped at names its own
        // number, which is copied.
        result[9] = head.Protocol == Icmpv6 ? ProtocolIcmpv4 : head.Protocol;
        source.GetAddressBytes().CopyTo(result.AsSpan(12));
        destination.GetAddressBytes().CopyTo(result.AsSpan(16));
        // §5.1: "Header Checksum: Computed once the IPv4 header has been created."
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(10), HeaderChecksum(result));
    }

    private static ushort HeaderChecksum(ReadOnlySpan<byte> header)
    {
        // RFC 791 §3.1: the 16-bit one's complement of the one's complement sum of the header's 16-bit words,
        // read with the checksum field itself zero - which it is in a header being written.
        return (ushort)~Fold(Add(0, header[..((header[0] & 0x0F) * 4)]));
    }

    // TCP and UDP over a datagram that came in whole: §5.5's "Translators MUST do this for TCP, UDP, and ICMP",
    // done by computing the checksum again over the new pseudo-header. A first fragment is the case RFC 6052
    // §4.1 and RFC 1624 §2 answer without the rest of the message: the two pseudo-headers differ only in their
    // address words, since each side adds the same protocol number and the same length figure, so the stored
    // checksum can be moved by that difference alone.
    private static byte[] TranslateTransport64(ReadOnlySpan<byte> transport, V6Header head, IPAddress source,
        IPAddress destination, IPAddress source6, IPAddress destination6)
    {
        var bytes = transport.ToArray();
        var field = head.Protocol == ProtocolUdp ? 6 : 16;
        if (!head.Fragmented)
        {
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(field, 2), 0);
            var sum = Fold(Add(0, Pseudo4(source, destination, head.Protocol, bytes.Length)) +
                            Add(0, bytes[..field]) + Add(0, bytes[field..]));
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(field, 2), (ushort)~sum);
            return bytes;
        }
        var stored = BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(field, 2));
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(field, 2),
            Update(stored, Pseudo6(source6, destination6, head.Protocol, bytes.Length),
                Pseudo4(source, destination, head.Protocol, bytes.Length)));
        return bytes;
    }

    // --- IPv4 to IPv6 -------------------------------------------------------------------------------------

    private static bool Translate46(ReadOnlySpan<byte> packet, AddressMap map, PathMtu path, bool asQuote,
        out byte[]? translated, out string why)
    {
        translated = null;
        why = "";
        if (!TryReadV4(packet, asQuote, out var head, out why)) return false;

        var source4 = new IPAddress(packet.Slice(12, 4).ToArray());
        var destination4 = new IPAddress(packet.Slice(16, 4).ToArray());
        if (!asQuote && head.Protocol != ProtocolIcmpv4 && IsIllegal(source4, out why)) return false;
        if (!map(source4, destination4, out var source, out var destination) ||
            source is null || destination is null || source.AddressFamily != AddressFamily.InterNetworkV6)
        {
            why = $"the mapping in use does not reach both {source4} and {destination4}";
            return false;
        }

        var hopLimit = (byte)head.TimeToLive;
        if (!asQuote)
        {
            // §4.1's zero check, the same sentence §5.1 repeats: "the translator (as any router) MUST check for
            // zero and send the ICMPv4 'TTL Exceeded' or ICMPv6 'Hop Limit Exceeded' error".
            if (hopLimit <= 1)
            {
                why = $"the TTL is {hopLimit}, so §4.1's zero check stops the packet here";
                return false;
            }
            hopLimit--;
        }

        var shape = default(Shape);
        var message = head.Protocol == ProtocolIcmpv4 ? packet[head.Transport..head.DatagramEnd] : ReadOnlySpan<byte>.Empty;
        if (head.Protocol == ProtocolIcmpv4)
        {
            if (head.Fragmented)
            {
                why = "the ICMPv4 message is a fragment, and §3 says a fragmented ICMP packet is not translated";
                return false;
            }
            if (message.Length < 8)
            {
                why = $"the ICMPv4 message at {head.Transport} is {message.Length} octets, short of the 8 its Type, Code and checksum need";
                return false;
            }
            var quotedTotal = message.Length - 8 >= Ipv4HeaderLength && message[8] >> 4 == 4
                ? BinaryPrimitives.ReadUInt16BigEndian(message.Slice(10, 2))
                : (ushort)0;
            if (!TryShape46(message, path, quotedTotal, out shape, out why)) return false;
        }

        ReadOnlySpan<byte> embedded = [];
        ReadOnlySpan<byte> tail = [];
        byte[]? quoted = null;
        if (shape.Error)
        {
            SplitQuote(message[8..], shape.GuaranteedBytes, false, out embedded, out tail);
            if (!TryReadV4(embedded, true, out var embeddedHead, out _))
            {
                why = "the packet quoted in the ICMPv4 error is not an IPv4 packet this translation can read";
                return false;
            }
            if (embeddedHead.Protocol == ProtocolIcmpv4 && QuoteIsError4(embedded, embeddedHead, path))
            {
                why = "§4.3 stops at the first embedded header and drops \"if it contains more embedded headers\", " +
                      "and the quoted ICMPv4 message is one of §4.2's error rows or one that table does not name";
                return false;
            }
            if (!Translate46(embedded, map, path, true, out quoted, out why)) return false;
        }

        var header = TransportHeaderLength(head.Protocol);
        var whole = head.FragmentOffset == 0 && head.Transport + header <= head.DatagramEnd;
        if (!asQuote && whole && head.Fragmented && head.Protocol == ProtocolUdp &&
            BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(head.Transport + 6, 2)) == 0)
        {
            // §4.5: "A stateless translator cannot compute the UDP checksum of fragmented packets, so when a
            // stateless translator receives the first fragment of a fragmented UDP IPv4 packet and the checksum
            // field is zero, the translator SHOULD drop the packet and generate a system management event that
            // specifies at least the IP addresses and port numbers in the packet."
            why = "the first fragment of a fragmented UDP packet carries no checksum, which §4.5 makes a stateless translator drop";
            return false;
        }

        byte[] body;
        if (head.Protocol == ProtocolIcmpv4)
            body = BuildIcmp(true, shape, quoted, embedded, tail, message, source, destination);
        else if (!asQuote && whole && head.Protocol is ProtocolTcp or ProtocolUdp)
            body = TranslateTransport46(packet[head.Transport..head.DatagramEnd], head, source, destination,
                source4, destination4);
        else
            body = packet[head.Transport..head.DatagramEnd].ToArray();

        // §4.1's Fragment Header case, which the paragraph before it limits to a packet that came in fragmented:
        // "When the IPv4 sender does not set the DF bit, the translator MUST NOT include the Fragment Header for
        // the non-fragmented IPv6 packets."
        var withFragment = head.Fragmented;
        var payloadLength = body.Length + (withFragment ? 8 : 0);
        if (payloadLength > ushort.MaxValue)
        {
            why = $"the {body.Length}-octet body leaves no 16-bit Payload Length for RFC 8200 §3's header to carry";
            return false;
        }

        var result = new byte[Ipv6Chain.HeaderLength + payloadLength];
        // §4.1: "Version: 6", "Traffic Class: By default, copied from the IP Type Of Service (TOS) octet", "Flow
        // Label: 0 (all zero bits)".
        result[0] = (byte)(0x60 | (packet[1] >> 4));
        result[1] = (byte)((packet[1] & 0x0F) << 4);
        // §4.1: "Payload Length: Total length value from the IPv4 header, minus the size of the IPv4 header and
        // IPv4 options, if present" - and in the fragment case, "plus 8 for the Fragment Header".
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), (ushort)payloadLength);
        // §4.1: "Next Header: For ICMPv4 (1), it is changed to ICMPv6 (58); otherwise, the protocol field MUST be
        // copied from the IPv4 header", and its fragment case names the Fragment Header in the base header
        // instead, leaving the number for the transport to the Fragment Header's own first octet.
        result[6] = withFragment ? NextFragment : head.Protocol == ProtocolIcmpv4 ? Icmpv6 : head.Protocol;
        result[7] = hopLimit;
        source.GetAddressBytes().CopyTo(result.AsSpan(8));
        destination.GetAddressBytes().CopyTo(result.AsSpan(24));

        if (!withFragment) body.CopyTo(result.AsSpan(Ipv6Chain.HeaderLength));
        else
        {
            var at = Ipv6Chain.HeaderLength;
            // §4.1's four Fragment Header rows: "Next Header: For ICMPv4 (1), it is changed to ICMPv6 (58);
            // otherwise, the protocol field MUST be copied from the IPv4 header", "Fragment Offset: Fragment
            // Offset copied from the IPv4 header", "M flag: More Fragments bit copied from the IPv4 header", and
            // "Identification: The low-order 16 bits copied from the Identification field in the IPv4 header. The
            // high-order 16 bits set to zero."
            result[at] = head.Protocol == ProtocolIcmpv4 ? Icmpv6 : head.Protocol;
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(at + 2),
                (ushort)(((head.FragmentOffset & 0x1FFF) << 3) | (head.MoreFragments ? 1 : 0)));
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(at + 4), head.Identification);
            body.CopyTo(result.AsSpan(at + 8));
        }

        translated = result;
        return true;
    }

    // RFC 791 §3.1's header, §4.1's fragment rows, and the TTL §4.1 derives the Hop Limit from.
    public readonly record struct V4Header(int Transport, byte Protocol, int DatagramEnd, bool Fragmented,
        int FragmentOffset, bool MoreFragments, uint Identification, int TimeToLive);

    public static bool TryReadV4(ReadOnlySpan<byte> packet, bool truncated, out V4Header head, out string why)
    {
        head = default;
        why = "";
        if (packet.Length < Ipv4HeaderLength)
        {
            why = $"an IPv4 header is {Ipv4HeaderLength} octets and only {packet.Length} are here";
            return false;
        }
        if (packet[0] >> 4 != 4)
        {
            why = $"the version field says {packet[0] >> 4}, not 4";
            return false;
        }
        var ihl = (packet[0] & 0x0F) * 4;
        if (ihl < Ipv4HeaderLength || ihl > packet.Length)
        {
            why = $"IHL says the header is {ihl} octets inside {packet.Length}";
            return false;
        }
        // RFC 791 §3.1's Total Length is "length of header and data in octets", so as with IPv6's Payload Length
        // the octets past it are padding rather than this datagram, and a buffer shorter than it is a datagram
        // that did not all arrive - except inside an error message, where §4.3's figure names a partial header.
        var declared = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(2, 2));
        if (declared > packet.Length && !truncated)
        {
            why = $"total length {declared} claims more than the {packet.Length} octets here";
            return false;
        }
        if (declared < ihl)
        {
            why = $"total length {declared} is short of the {ihl}-octet header it carries";
            return false;
        }
        var end = Math.Min(declared, packet.Length);

        if (!truncated && Fold(Add(0, packet[..ihl])) != 0xFFFF)
        {
            // RFC 791 §3.1's Header Checksum is "the 16-bit one's complement of the one's complement sum of all
            // 16-bit words in the header", which makes a whole header sum to all ones when the field is read as
            // it stands. A quoted header skips the test because the sender's own hop may already have rewritten
            // it, and §4.3 asks for the copy to be translated either way.
            why = "the IPv4 header checksum does not verify, so the header is not one to translate";
            return false;
        }

        // §4.1: "If any IPv4 options are present in the IPv4 packet, they MUST be ignored and the packet
        // translated normally; there is no attempt to translate the options. However, if an unexpired source
        // route option is present, then the packet MUST instead be discarded, and an ICMPv4 'Destination
        // Unreachable, Source Route Failed' (Type 3, Code 5) error message SHOULD be returned to the sender."
        if (HasSourceRoute(packet[Ipv4HeaderLength..ihl]))
        {
            why = "a source route option is present, which §4.1 discards rather than dropping it with the other options, and asks for a Type 3 Code 5";
            return false;
        }

        var flags = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(6, 2));
        head = new V4Header(ihl, packet[9], end,
            (flags & 0x2000) != 0 || (flags & 0x1FFF) != 0,
            flags & 0x1FFF, (flags & 0x2000) != 0,
            BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(4, 2)), packet[8]);
        return true;
    }

    // RFC 791 §3.1's option list, walked for the two source route options alone: 130 is the strict route and 131
    // the loose one, each with a type, a length and a Pointer before its addresses - and an unexpired one still
    // has a hop left to visit, which is what the Pointer pointing into the list says.
    private static bool HasSourceRoute(ReadOnlySpan<byte> options)
    {
        for (var i = 0; i + 1 < options.Length;)
        {
            switch (options[i])
            {
                case 0: return false;
                case 1: i++; continue;
                case 130 or 131:
                    if (i + 3 >= options.Length) return false;
                    if (options[i + 2] < options[i + 1]) return true;
                    break;
            }
            var length = options[i + 1];
            if (length < 2) return false;
            i += length;
        }
        return false;
    }

    // §4.5's recompute, and RFC 1624 §2's move of a stored checksum for a first fragment. RFC 8200 §8.1 adds the
    // rule for the IPv6 side: "whenever originating a UDP packet, an IPv6 node must compute a UDP checksum over
    // the packet and the pseudo-header, and, if that computation yields a result of zero, it must be changed to
    // hex FFFF for placement in the UDP header." A UDP packet arriving whole with no checksum takes §4.5's second
    // configuration choice, "Calculating an IPv6 checksum and forwarding the packet".
    private static byte[] TranslateTransport46(ReadOnlySpan<byte> transport, V4Header head, IPAddress source,
        IPAddress destination, IPAddress source4, IPAddress destination4)
    {
        var bytes = transport.ToArray();
        var field = head.Protocol == ProtocolUdp ? 6 : 16;
        if (!head.Fragmented)
        {
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(field, 2), 0);
            var sum = Fold(Add(0, Pseudo6(source, destination, head.Protocol, bytes.Length)) +
                            Add(0, bytes[..field]) + Add(0, bytes[field..]));
            var value = (ushort)~sum;
            if (head.Protocol == ProtocolUdp && value == 0) value = 0xFFFF;
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(field, 2), value);
            return bytes;
        }
        var stored = BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(field, 2));
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(field, 2),
            Update(stored, Pseudo4(source4, destination4, head.Protocol, bytes.Length),
                Pseudo6(source, destination, head.Protocol, bytes.Length)));
        return bytes;
    }

    // --- the ICMP message, the quoted packet inside it, and their checksums ---------------------------------

    // Where the quoted datagram ends inside an error message, and what follows it. RFC 4884 §5.4: "If the length
    // attribute is zero, the compliant application MUST determine that the message contains no extensions", so
    // with no attribute the embedded header's own length says how much of the datagram the sender quoted, and
    // the octets after that are the opaque bit strings §4.2's and §5.2's "ICMP Error Payload" paragraphs pass
    // along untranslated.
    private static void SplitQuote(ReadOnlySpan<byte> region, int guaranteedBytes, bool v6,
        out ReadOnlySpan<byte> quoted, out ReadOnlySpan<byte> tail)
    {
        var declared = v6
            ? region.Length >= Ipv6Chain.HeaderLength && region[0] >> 4 == 6
                ? Ipv6Chain.HeaderLength + BinaryPrimitives.ReadUInt16BigEndian(region.Slice(4, 2))
                : 0
            : region.Length >= Ipv4HeaderLength && region[0] >> 4 == 4
                ? BinaryPrimitives.ReadUInt16BigEndian(region.Slice(2, 2))
                : 0;
        var length = guaranteedBytes > 0 ? Math.Min(guaranteedBytes, region.Length)
            : declared > 0 ? Math.Min(declared, region.Length)
            : region.Length;
        quoted = region[..length];
        tail = region[length..];
    }

    // The translated message: §4.2's or §5.2's Type and Code, the second word each pair of messages puts its
    // pointer, MTU and RFC 4884 length attribute into, the header quoted inside it translated by the same
    // function that is building this one, and everything else carried along.
    //
    // RFC 4884's attribute moves with the translation because §4.2's and §5.2's "ICMP Error Payload" paragraphs
    // say it MUST: "the translation of the ICMPv4 packet will cause the ICMPv6 packet to change length. When this
    // occurs, the ICMPv6 Extension length attribute MUST be adjusted accordingly". It counts 32-bit words over
    // IPv4 and 64-bit words over IPv6 - §4.1 through §4.5 of that document - so the guaranteed region is shifted
    // by the delta the quoted header changed by and recounted in the new unit.
    //
    // RFC 4443 §2.4 (c) is the other bound on the IPv6 side: "Every ICMPv6 error message (type < 128) MUST
    // include as much of the IPv6 offending (invoking) packet ... as possible without making the error message
    // packet exceed the minimum IPv6 MTU", and §4.2's sentence for the same case is "If the ICMPv4 Extension
    // exceeds the maximum size of an ICMPv6 message on the outgoing interface, the ICMPv4 extension SHOULD be
    // simply truncated". The extension goes first, then the quoted datagram down to whole 64-bit words.
    private static byte[] BuildIcmp(bool toV6, in Shape shape, byte[]? quoted, ReadOnlySpan<byte> embedded,
        ReadOnlySpan<byte> tail, ReadOnlySpan<byte> message, IPAddress source, IPAddress destination)
    {
        var unit = toV6 ? 8 : 4;
        var guaranteed = shape.GuaranteedBytes == 0 || quoted is null
            ? 0
            : Math.Clamp(shape.GuaranteedBytes + quoted.Length - embedded.Length, 0, quoted.Length);
        if (toV6 && shape.Error)
        {
            var room = MinimumIpv6Mtu - Ipv6Chain.HeaderLength - 8;
            if (quoted!.Length + tail.Length > room) tail = [];
            if (quoted.Length > room)
            {
                quoted = quoted[..(room / unit * unit)];
                guaranteed = Math.Min(guaranteed, quoted.Length);
            }
        }

        var body = new byte[8 + (shape.Error ? quoted!.Length + tail.Length : message.Length - 8)];
        body[0] = shape.Type;
        body[1] = shape.Code;

        var lengthAt = -1;
        if (!shape.Error)
        {
            // The informational messages keep their own second word: RFC 792 §1.9 and RFC 4443 §4.1 both put the
            // Echo Request's Identifier and Sequence Number there, and §4.2 and §5.2 change only the Type.
            message.Slice(4, 4).CopyTo(body.AsSpan(4));
            message[8..].CopyTo(body.AsSpan(8));
        }
        else if (toV6)
        {
            switch (shape.Type)
            {
                // RFC 4443 §2.4's figure for every error message, and RFC 4884 §4.4 and §4.5's length attribute
                // in the fifth octet of the Destination Unreachable and the Time Exceeded.
                case 1 or 3:
                    lengthAt = 4;
                    break;
                // RFC 4443 §3.2: the Packet Too Big message's second word is its 32-bit MTU.
                case 2:
                    BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(4), shape.Mtu);
                    break;
                // RFC 4443 §3.4: the Parameter Problem's is its Pointer and three reserved octets.
                default:
                    body[4] = (byte)shape.Pointer;
                    break;
            }
            quoted!.CopyTo(body.AsSpan(8));
            tail.CopyTo(body.AsSpan(8 + quoted.Length));
        }
        else
        {
            switch (shape.Type)
            {
                // RFC 792 §1.13's Time Exceeded and §1.15's Parameter Problem second words: RFC 4884 §4.2 and
                // §4.3 put the length attribute in the sixth octet, and Parameter Problem keeps the Pointer RFC
                // 792 gave it in the fifth.
                case 11:
                    lengthAt = 5;
                    break;
                case 12:
                    body[4] = (byte)shape.Pointer;
                    lengthAt = 5;
                    break;
                // RFC 792 §1.3's Destination Unreachable: unused, then RFC 4884 §4.1's attribute in the sixth
                // octet, then the 16-bit Next-Hop MTU that only its Code 4 carries.
                default:
                    lengthAt = 5;
                    if (shape.HasMtu) BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(6), (ushort)shape.Mtu);
                    break;
            }
            quoted!.CopyTo(body.AsSpan(8));
            tail.CopyTo(body.AsSpan(8 + quoted.Length));
        }

        if (lengthAt >= 0) body[lengthAt] = (byte)Math.Min(guaranteed / unit, byte.MaxValue);

        // The ICMP checksum, which both directions owe the message: §4.2 opens with "All ICMPv4 messages that are
        // to be translated require that the ICMPv6 checksum field be calculated as part of the translation since
        // ICMPv6, unlike ICMPv4, has a pseudo-header checksum just like UDP and TCP", and §5.2 with the mirror of
        // that sentence. The IPv6 side's pseudo-header is RFC 8200 §8.1's, whose trail is the 32-bit length and
        // the value 58 that RFC 4443 §2.3 describes.
        var sum = toV6
            ? Add(0, Pseudo6(source, destination, Icmpv6, body.Length)) + Add(0, body)
            : Add(0, body);
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(2, 2), (ushort)~Fold(sum));
        return body;
    }

    // --- shared arithmetic, and the illegal addresses -----------------------------------------------------------------

    // RFC 1624 §2's "HC' = ~(C + (-m) + m')", with C the sum the stored checksum is the complement of, applied to
    // every word the two pseudo-headers differ in. They are different lengths, so the words of the longer one
    // past the end of the shorter move as the whole of their contribution - which is the whole of what a
    // stateless translator has to offer, since the protocol number and the length figure each side adds up to
    // the same words and only the addresses differ.
    private static ushort Update(ushort stored, ReadOnlySpan<byte> oldPseudo, ReadOnlySpan<byte> newPseudo)
    {
        var words = Math.Max(oldPseudo.Length, newPseudo.Length) / 2;
        for (var i = 0; i < words; i++)
        {
            var at = i * 2;
            var old = at < oldPseudo.Length ? BinaryPrimitives.ReadUInt16BigEndian(oldPseudo[at..]) : (ushort)0;
            var next = at < newPseudo.Length ? BinaryPrimitives.ReadUInt16BigEndian(newPseudo[at..]) : (ushort)0;
            if (old == next) continue;
            stored = (ushort)~Fold((uint)(~stored & 0xFFFF) + (uint)(~old & 0xFFFF) + next);
        }
        return stored;
    }

    // RFC 791 §3.1's pseudo-header for IPv4: source, destination, one zero octet, the protocol, and the 16-bit
    // upper-layer length. RFC 9293 §3.1's figure 2 is where those five fields come from.
    private static byte[] Pseudo4(IPAddress source, IPAddress destination, byte protocol, int length)
    {
        var pseudo = new byte[12];
        source.GetAddressBytes().CopyTo(pseudo, 0);
        destination.GetAddressBytes().CopyTo(pseudo, 4);
        pseudo[9] = protocol;
        BinaryPrimitives.WriteUInt16BigEndian(pseudo.AsSpan(10, 2), (ushort)length);
        return pseudo;
    }

    // RFC 8200 §8.1's for IPv6: the two 16-octet addresses, a 32-bit upper-layer length, three zero octets and the
    // next-header value.
    private static byte[] Pseudo6(IPAddress source, IPAddress destination, byte protocol, int length)
    {
        var pseudo = new byte[40];
        source.GetAddressBytes().CopyTo(pseudo, 0);
        destination.GetAddressBytes().CopyTo(pseudo, 16);
        BinaryPrimitives.WriteUInt32BigEndian(pseudo.AsSpan(32, 4), (uint)length);
        pseudo[39] = protocol;
        return pseudo;
    }

    // RFC 1071 §1's sum over 16-bit words, with an odd last octet padded on the right by zero, and the
    // end-around carry that closes it.
    private static uint Add(uint sum, ReadOnlySpan<byte> data)
    {
        var offset = 0;
        for (; offset + 1 < data.Length; offset += 2)
            sum += BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset, 2));
        if (offset < data.Length) sum += (uint)(data[offset] << 8);
        return sum;
    }

    private static uint Fold(uint sum)
    {
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return sum;
    }

    // §4.1's "illegal source address (e.g., 0.0.0.0, 127.0.0.1, etc.)", which §4.1 points at RFC 1812 §5.3.7: "A
    // router SHOULD NOT forward any packet that has an invalid IP source address or a source address on network
    // 0. A router SHOULD NOT forward, except over a loopback interface, any packet that has a source address on
    // network 127", invalid being "a special IP address ... or is not a unicast address". §5.1's "(e.g., ::1,
    // etc.)" is the same rule one family over, and RFC 4291 is where its four cases are kept: §2.5.3's "The
    // loopback address must not be used as the source address in IPv6 packets", §2.7's "Multicast addresses must
    // not be used as source addresses in IPv6 packets", §2.5.2's unspecified address, and §2.5.6's "Routers must
    // not forward any packets with Link-Local source or destination addresses to other links."
    private static bool IsIllegal(IPAddress address, out string why)
    {
        var bytes = address.GetAddressBytes();
        var illegal = address.AddressFamily switch
        {
            AddressFamily.InterNetwork => bytes[0] is 0 or 127 or >= 224,
            AddressFamily.InterNetworkV6 => IPAddress.IsLoopback(address) || address.IsIPv6LinkLocal ||
                bytes[0] == 0xff ||
                bytes[0] == 0 && bytes.AsSpan(1, 15).IndexOfAnyExcept((byte)0) < 0,
            _ => true
        };
        why = illegal ? $"{address} is not an address a router forwards a packet from" : "";
        return illegal;
    }
}
