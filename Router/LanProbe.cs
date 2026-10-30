using System.Buffers.Binary;

namespace Router;

/// <summary>
/// One inbound UDP datagram aimed at one of this program's own listeners, and the answer to it.
///
/// The rule store cannot say whether a client's packet reaches port 67 or 53 on the LAN interface, for the
/// reason TlsMitm.InboundFirewall spells out: the rules that grant a service port report a wildcard there,
/// and an explicit block outranks an allow however narrow the allow is. So the question is asked with a
/// packet instead, from an address inside the LAN subnet to the address the listener is bound to.
///
/// For UDP the listener is the whole witness, which is not how the relay's probe works. A datagram the
/// filter lets through is delivered to the bound socket, so the socket's own count answers it; a lone TCP
/// SYN is never handed to an accept queue, which is why that one had to be read out of the connection
/// table instead.
///
/// What this does not ask: a client that has no address yet sends its DISCOVER as a broadcast from
/// 0.0.0.0:68, and this probe is unicast from an address in the subnet. The inbound filter decides on
/// protocol and port for both shapes, and the difference between them is how the stack delivers a
/// broadcast to a bound socket - a binding question, which the lease a real client is handed tests.
/// </summary>
public sealed class LanProbe(string name, ushort destinationPort, uint source, ushort token)
{
    /// The payload's first eight octets. Read as a BOOTP message, their first is neither 1 nor 2, the only
    /// two values of 'op' (RFC 2131 §2). Read as a DNS header they give an ID of 0x6C61, flags of 0x6E70
    /// and a question count of 29295 — a message neither of the two servers answers, which tests/servcheck
    /// pins by feeding these bytes to both.
    public static ReadOnlySpan<byte> Marker => "lanprobe"u8;

    public ushort Token => token;
    public uint Source => source;

    /// Which listener this was aimed at, for the lines that name it.
    public string Name => name;

    /// The port the listener is bound to, which is what the answer is about.
    public ushort DestinationPort => destinationPort;

    /// A source port for a probe whose protocol has no client port of its own. The filter decides on the
    /// destination, so all this has to be is plausible: the start of RFC 6335 §5.2.1's Dynamic range,
    /// where a client's ephemeral port lives.
    public const ushort EphemeralSourcePort = 49152;

    private int _arrivals;

    /// How many times this probe has been delivered to the listener it was aimed at.
    public int Arrivals => Volatile.Read(ref _arrivals);

    /// The address a probe is sent from: one below the subnet's last. Inside the LAN, so a rule scoped to
    /// the subnet is exercised rather than dodged, and neither this host's own address nor the all-ones
    /// address of <see cref="DhcpConfig.BroadcastAddress"/>. The arithmetic is the wire order the project's
    /// uint form already holds, so counting down takes the last octet off.
    public static uint ProbeSource(uint lanAddress, uint mask) => (lanAddress | ~mask) - 1;

    /// The IPv4 and UDP header fields in wire order, with both checksums left zero for the driver's
    /// CalcChecksums to fill on the way in.
    public byte[] Build(uint destination, ushort sourcePort)
    {
        var payload = new byte[Marker.Length + 2];
        Marker.CopyTo(payload);
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(Marker.Length), token);

        var packet = new byte[Ipv4Header + UdpHeader + payload.Length];
        packet[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), (ushort)packet.Length);
        packet[8] = 64;
        // RFC 791's "protocol" field, and RFC 768 is 17.
        packet[9] = 17;
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(12), source);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(16), destination);

        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(Ipv4Header), sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(Ipv4Header + 2), destinationPort);
        // RFC 768's length member covers the UDP header and its data, not the IPv4 header above it.
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(Ipv4Header + 4), (ushort)(UdpHeader + payload.Length));
        payload.CopyTo(packet, Ipv4Header + UdpHeader);
        return packet;
    }

    /// Whether a datagram a listener just received is this probe, and if so, taking it. The count is the
    /// verdict, so a probe must never reach the server behind it: an unanswered DISCOVER would still have
    /// reserved a lease, and a bogus query would be logged as a client's.
    public bool Consume(byte[] datagram, uint fromAddress)
    {
        if (fromAddress != source) return false;
        if (datagram.Length != Marker.Length + 2) return false;
        if (!datagram.AsSpan(0, Marker.Length).SequenceEqual(Marker)) return false;
        if (BinaryPrimitives.ReadUInt16BigEndian(datagram.AsSpan(Marker.Length)) != token) return false;
        Interlocked.Increment(ref _arrivals);
        return true;
    }

    private const int Ipv4Header = 20;

    /// RFC 768: source port, destination port, length and checksum, two octets each.
    private const int UdpHeader = 8;
}
