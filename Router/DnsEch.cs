using System.Buffers.Binary;

namespace Router;

// The resolver in this process can only take the ECH configuration away from the clients it answers;
// this is the same rewrite for an answer that never passes through it - the host's own resolver
// traffic, which is local delivery and therefore belongs to the reply leg rather than the forwarding
// one. RFC 9848 §3 puts the configuration in the HTTPS record's "ech" SvcParamKey, so taking the key
// out of the record is the whole job (DnsFormat.NeutralizeEch), and all that is left here is finding
// the message inside the packet. Nothing is resized, so the caller only has to redo the checksums.
public static class DnsEch
{
    // How many "ech" parameters were rewritten in place; zero means the packet was left alone.
    public static int TryNeutralize(Span<byte> packet)
    {
        if (packet.Length < 20 || (packet[0] >> 4) != 4) return 0;
        var ihl = (packet[0] & 0x0F) * 4;
        if (ihl < 20 || packet.Length < ihl + 8) return 0;

        // RFC 791 §3.2 splits a datagram with the flags and fragment offset; a fragment's DNS message
        // is not in it to be read, and a rewrite that keeps every length cannot stitch one together.
        if ((BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(6, 2)) & 0x3FFF) != 0) return 0;

        var protocol = packet[9];
        if (protocol is not (6 or 17)) return 0;
        if (BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ihl, 2)) != DnsPorts.ServerPort) return 0;

        // The IP total length is the datagram; anything the capture added behind it is not part of it.
        var total = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(2, 2));
        var end = total >= 20 && total <= packet.Length ? total : packet.Length;

        if (protocol == 17)
        {
            // RFC 768 gives the UDP length as the header and its data, so the payload ends at it.
            var udpLength = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ihl + 4, 2));
            if (udpLength < 8 || ihl + udpLength > end) return 0;
            return DnsFormat.NeutralizeEch(packet.Slice(ihl + 8, udpLength - 8));
        }

        if (packet.Length < ihl + 20) return 0;
        var dataOffset = (packet[ihl + 12] >> 4) * 4;
        if (dataOffset < 20 || ihl + dataOffset + 2 > end) return 0;
        var payload = packet.Slice(ihl + dataOffset, end - ihl - dataOffset);
        // RFC 1035 §4.2.2 carries a message behind a two-octet length. A segment holding only part of
        // one is not rewritten: that would take reassembling the stream, and the length here is the
        // record of where the message is.
        var messageLength = BinaryPrimitives.ReadUInt16BigEndian(payload);
        if (2 + messageLength > payload.Length) return 0;
        return DnsFormat.NeutralizeEch(payload.Slice(2, messageLength));
    }
}
