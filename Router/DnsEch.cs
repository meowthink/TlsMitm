using System.Buffers.Binary;

namespace Router;

// The resolver in this process can only take the ECH configuration away from the clients it answers;
// this is the same rewrite for an answer that never passes through it - the host's own resolver
// traffic, which is local delivery and therefore belongs to the reply leg rather than the forwarding
// one. RFC 9848 §3 puts the configuration in the HTTPS record's "ech" SvcParamKey, so taking the key
// out of the record is the whole job (DnsFormat.NeutralizeEch), and all that is left here is finding
// the message inside the packet. Nothing is resized, so the caller only has to redo the checksums -
// which the driver's recalculating call does for both families and for a transport that sits behind an
// extension header: measured offline in tests/servcheck, where the checksum it writes for each of the
// four shapes is compared with the RFC 8200 §8.1 figure computed by hand.
public static class DnsEch
{
    // How many "ech" parameters were rewritten in place; zero means the packet was left alone.
    public static int TryNeutralize(Span<byte> packet)
    {
        if (packet.Length < 2) return 0;
        return (packet[0] >> 4) switch
        {
            4 => TryNeutralizeV4(packet),
            6 => TryNeutralizeV6(packet),
            _ => 0
        };
    }

    private static int TryNeutralizeV4(Span<byte> packet)
    {
        if (packet.Length < 20) return 0;
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

        return protocol == 17
            ? NeutralizeUdp(packet, ihl + 8, end - ihl - 8)
            : NeutralizeTcp(packet, ihl, end);
    }

    private static int TryNeutralizeV6(Span<byte> packet)
    {
        // One walk, in the file the proxy's redirector walks too: TlsMitm/Ipv6Chain.cs, linked into this
        // assembly the way the driver's P/Invoke surface is. It answers where the transport begins and
        // which number says it is the transport, and it refuses a fragment, §4.7's No Next Header, a
        // header with no length figure to read and a chain reaching past the payload the base header
        // declared. Its AddressDependent answer stops the rewrite as well as the read: §4.4's routing
        // header "is used by an IPv6 source to list one or more intermediate nodes to be visited", and
        // RFC 4302 §3.3.3 computes an Auth Header's ICV over the fields in front of it and "everything
        // after AH", so a record taken out of the payload would leave the packet still claiming something
        // the rewrite made false - and a claim no peer can check is one it discards.
        if (!TlsMitm.Ipv6Chain.TryFind(packet, out var chain) || chain.AddressDependent) return 0;

        // The first port is the sender's, and the resolver's port is what names an answer; a query on
        // its way out has no records to rewrite.
        if (BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(chain.Transport, 2)) != DnsPorts.ServerPort) return 0;

        return chain.Protocol == 17
            ? NeutralizeUdp(packet, chain.Transport + 8, chain.DatagramEnd - chain.Transport - 8)
            : NeutralizeTcp(packet, chain.Transport, chain.DatagramEnd);
    }

    // transportStart is the UDP payload's first octet; available is the datagram's room behind it.
    private static int NeutralizeUdp(Span<byte> packet, int transportStart, int available)
    {
        if (available < 0 || transportStart < 0) return 0;
        if (transportStart - 8 + 8 > packet.Length) return 0;             // the header must be all there
        // RFC 768 gives the UDP length as the header and its data, so the payload ends at it.
        var udpLength = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(transportStart - 4, 2));
        if (udpLength < 8 || udpLength > available + 8) return 0;
        return DnsFormat.NeutralizeEch(packet.Slice(transportStart, udpLength - 8));
    }

    // transportStart is the first octet of the transport header; end is the datagram's last octet.
    private static int NeutralizeTcp(Span<byte> packet, int transportStart, int end)
    {
        if (transportStart + 20 > packet.Length || end < transportStart + 22) return 0;
        var dataOffset = (packet[transportStart + 12] >> 4) * 4;
        if (dataOffset < 20) return 0;
        var payloadStart = transportStart + dataOffset;
        if (payloadStart + 2 > end || payloadStart >= packet.Length) return 0;
        // RFC 1035 §4.2.2 carries a message behind a two-octet length. A segment holding only part of
        // one is not rewritten: that would take reassembling the stream, and the length here is the
        // record of where the message is.
        var messageLength = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(payloadStart, 2));
        if (2 + (long)messageLength > end - payloadStart) return 0;
        if (payloadStart + 2 + messageLength > packet.Length) return 0;
        return DnsFormat.NeutralizeEch(packet.Slice(payloadStart + 2, messageLength));
    }
}
