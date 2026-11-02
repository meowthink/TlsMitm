using System.Buffers.Binary;

namespace TlsMitm;

/// RFC 8200 §3's chain, walked once for both programs that read an IPv6 packet: the proxy's redirector
/// swaps a flow's addresses and ports, the router's reply leg rewrites a DNS answer inside it, and the
/// trace names what it is looking at. Its Next Header "identifies the type of header immediately
/// following the IPv6 header", and every extension header opens with the same kind of number naming the
/// header behind it (§4.3's words for a hop-by-hop: "Identifies the type of header immediately following
/// the Hop-by-Hop Options header"), so the transport sits at the end of a walk rather than at octet 40.
/// One walk here means a header in front of the transport cannot leave one reader finding the message and
/// another losing the flow.
public static class Ipv6Chain
{
    public const int HeaderLength = 40;

    /// Where the transport header begins, which number says it is the transport, and the first octet past
    /// the region the base header declared. <see cref="AddressDependent"/> says the chain also carried a
    /// header whose own contents name addresses, which a rewrite of the base header would leave false.
    public readonly record struct Found(int Transport, byte Protocol, int DatagramEnd, bool AddressDependent);

    /// False when the chain cannot be trusted to hand over a transport: §4.5's fragment header, §4.7's
    /// No Next Header, a header this walk has no length figure for, anything reaching past the packet or
    /// past the payload the base header declared, and a chain of more than eight headers.
    public static bool TryFind(ReadOnlySpan<byte> packet, out Found found)
    {
        found = default;
        if (packet.Length < HeaderLength) return false;

        // §3: Payload Length is "Length of the IPv6 payload, i.e., the rest of the packet following this
        // IPv6 header, in octets", and extension headers are "considered part of the payload, i.e.,
        // included in the length count" - so the declared region is what the walk may read, and a capture
        // longer than it carries something that is not part of this datagram.
        var payloadLength = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(4, 2));
        var end = Math.Min(HeaderLength + payloadLength, packet.Length);
        var next = packet[6];
        var offset = HeaderLength;
        var addressDependent = false;
        var hops = 0;

        while (true)
        {
            // §4.5's Fragment header is identified by 44, and its Next Header "identifies the initial
            // header type of the Fragmentable Part of the original packet" - a walk that trusted it would
            // trust the header type of a message that is not all here, because §4.5's own offset and M
            // flag say which part this is. §4.7: the value 59 "indicates that there is nothing following
            // that header".
            if (next is 44 or 59) return false;
            if (next is 6 or 17) break;
            // Two octets have to be there to read a header's number and the length octet after it, and a
            // chain of headers at least eight octets each cannot reach past the payload the base header
            // declared, so the hop count is a belt to the bounds above rather than the thing that stops it.
            if (offset + 2 > packet.Length || ++hops > 8) return false;

            var following = packet[offset];
            var extLength = next switch
            {
                // §4.3's Hdr Ext Len is "Length of the Hop-by-Hop Options header in 8-octet units, not
                // including the first 8 octets"; §4.6 gives a destination options header (60) and §4.4 a
                // routing header (43) the same figure and the same wording.
                0 or 43 or 60 => (packet[offset + 1] + 1) * 8,
                // §3 says AH is specified in RFC 4302 rather than here; its §2.2 is "the length of AH in
                // 32-bit words (4-byte units), minus 2", so the two come back before multiplying.
                51 => (packet[offset + 1] + 2) * 4,
                // §3 says ESP is RFC 4303's, and its §2 has the packet "begin with two 4-byte fields" and
                // put the Next Header after the Payload Data and Padding - at the end, where a walk from
                // the front cannot reach it. Anything else this parser has no figure for is refused too.
                _ => -1
            };
            if (extLength < 8 || offset + extLength > packet.Length || offset + extLength > end) return false;

            // §4.4's routing header "is used by an IPv6 source to list one or more intermediate nodes to
            // be visited", and RFC 4302 §3.3.3 computes an Auth Header's ICV over the header fields in
            // front of it and "everything after AH", which is the payload. Both would go on saying
            // something the rewrite makes false, so the walk steps over them - a reader still needs to
            // know where the transport is - and reports that it found one.
            addressDependent |= next is 43 or 51;
            offset += extLength;
            next = following;
        }

        // The transport header has to be all there, inside both the capture and the declared region:
        // §8.1's pseudo-header is built from what follows, and a rewrite cannot sign a fragment of one.
        var octets = next == 17 ? 8 : 20;
        if (offset + octets > packet.Length || offset + octets > end) return false;

        found = new Found(offset, next, end, addressDependent);
        return true;
    }
}
