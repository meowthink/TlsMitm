using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace TlsMitm;

public class PcapWriter : IDisposable
{
    private readonly FileStream _stream;
    private readonly BinaryWriter _writer;
    private readonly object _gate = new();
    private uint _packetCount;

    // The wall clock anchors the file; Stopwatch carries the spacing between records.
    private readonly long _wallClockMicros;
    private readonly long _startTimestamp;
    private bool _opened;

    // Next sequence number of each direction. Wireshark reassembles a stream off these, so repeating
    // one constant turns every frame after the first into a "suspected retransmission" and leaves the
    // payload undissected.
    private uint _seqClientToServer = 1;
    private uint _seqServerToClient = 1;

    public PcapWriter(string filePath)
    {
        _stream = new FileStream(filePath, FileMode.Create, FileAccess.Write);
        _writer = new BinaryWriter(_stream);
        _packetCount = 0;
        _wallClockMicros = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1000;
        _startTimestamp = Stopwatch.GetTimestamp();

        WriteGlobalHeader();
    }

    private void WriteGlobalHeader()
    {
        // Magic number (little-endian)
        _writer.Write(0xa1b2c3d4u);
        // Version major
        _writer.Write((ushort)2);
        // Version minor
        _writer.Write((ushort)4);
        // Thiszone (GMT to local correction)
        _writer.Write(0);
        // Sigfigs (accuracy of timestamps)
        _writer.Write(0u);
        // Snaplen (max length of captured packets)
        _writer.Write(65535u);
        // Network (LINKTYPE_ETHERNET = 1)
        _writer.Write(1u);
    }

    public void WritePacket(byte[] packetData, bool isOutbound, IPAddress srcIp, IPAddress dstIp, ushort srcPort, ushort dstPort)
    {
        // Both relay directions call this at once; a record header and its payload must not interleave.
        lock (_gate) WritePacketCore(packetData, isOutbound, srcIp, dstIp, srcPort, dstPort);
    }

    private void WritePacketCore(byte[] packetData, bool isOutbound, IPAddress srcIp, IPAddress dstIp, ushort srcPort, ushort dstPort)
    {
        OpenFlow(isOutbound, srcIp, dstIp, srcPort, dstPort);

        // Neither IPv4's total-length field (RFC 791 §3.1) nor IPv6's payload-length field (RFC 8200
        // §3) can express more than 65535 octets, so a longer relay chunk has to become several
        // segments instead of wrapping the field and leaving the rest of the flow undissectable. The
        // 14 extra octets keep the frame within this file's snaplen; the relay reads 8 KB at a time,
        // so the split is a correctness guard, not a live path.
        const int MaxPayload = 65535 - 14 - 20 - 20;
        var offset = 0;
        do
        {
            var length = Math.Min(MaxPayload, packetData.Length - offset);
            var slice = length == packetData.Length ? packetData : packetData[offset..(offset + length)];
            WriteRecord(slice, isOutbound, srcIp, dstIp, srcPort, dstPort);
            offset += length;
        }
        while (offset < packetData.Length);
    }

    /// <summary>
    /// Prepends the three-way opening to the file. A capture that begins mid-stream leaves Wireshark
    /// unable to tell the start of a connection from a piece out of its middle, so the three segments
    /// are synthesized for this file's two endpoints with ISN 0 - which keeps the first data byte at
    /// sequence 1. No FIN is written: where the relay stopped is not where the session ended.
    /// </summary>
    private void OpenFlow(bool isOutbound, IPAddress srcIp, IPAddress dstIp, ushort srcPort, ushort dstPort)
    {
        if (_opened) return;
        _opened = true;

        var clientIp = isOutbound ? srcIp : dstIp;
        var serverIp = isOutbound ? dstIp : srcIp;
        var clientPort = isOutbound ? srcPort : dstPort;
        var serverPort = isOutbound ? dstPort : srcPort;

        WriteSegment(Array.Empty<byte>(), clientIp, serverIp, clientPort, serverPort, 0, 0, 0x02);
        WriteSegment(Array.Empty<byte>(), serverIp, clientIp, serverPort, clientPort, 0, 1, 0x12);
        WriteSegment(Array.Empty<byte>(), clientIp, serverIp, clientPort, serverPort, 1, 1, 0x10);
    }

    private void WriteRecord(byte[] payload, bool isOutbound, IPAddress srcIp, IPAddress dstIp, ushort srcPort, ushort dstPort)
    {
        // Build Ethernet + IP + TCP packet
        var seq = isOutbound ? _seqClientToServer : _seqServerToClient;
        var ack = isOutbound ? _seqServerToClient : _seqClientToServer;
        // Wraps at 2^32 exactly like a real sequence number (RFC 9293 §3.4: all sequence-number
        // arithmetic is modulo 2^32).
        if (isOutbound) _seqClientToServer += (uint)payload.Length;
        else _seqServerToClient += (uint)payload.Length;

        WriteSegment(payload, srcIp, dstIp, srcPort, dstPort, seq, ack,
            isOutbound ? (byte)0x18 : (byte)0x10); // PSH+ACK outbound, ACK inbound
    }

    private void WriteSegment(byte[] payload, IPAddress srcIp, IPAddress dstIp, ushort srcPort,
        ushort dstPort, uint seq, uint ack, byte flags)
    {
        var ethIpTcp = BuildPacket(payload, srcIp, dstIp, srcPort, dstPort, seq, ack, flags);
        var (timestamp, microseconds) = Stamp();

        _writer.Write(timestamp);           // ts_sec
        _writer.Write(microseconds);        // ts_usec
        _writer.Write((uint)ethIpTcp.Length); // incl_len
        _writer.Write((uint)ethIpTcp.Length); // orig_len

        // Packet data
        _writer.Write(ethIpTcp);

        _packetCount++;
    }

    private (uint Seconds, uint Microseconds) Stamp()
    {
        // DateTimeOffset.UtcNow advances in whole milliseconds on this host, so every record written
        // inside one millisecond shares a timestamp - a busy flow then has no order Wireshark can
        // show. The sub-second field still holds true microseconds: the wall clock fixes the file's
        // absolute time, and QPC, which counts at Stopwatch.Frequency, carries the spacing.
        var elapsed = (long)Stopwatch.GetElapsedTime(_startTimestamp).TotalMicroseconds;
        var micros = _wallClockMicros + elapsed;
        return ((uint)(micros / 1_000_000), (uint)(micros % 1_000_000));
    }

    private byte[] BuildPacket(byte[] payload, IPAddress srcIp, IPAddress dstIp,
        ushort srcPort, ushort dstPort, uint seq, uint ack, byte flags)
    {
        // The capture is one synthetic flow, so a client on v4 and a server on v6 cannot both keep
        // their own family: both endpoints are carried as v6, the v4 one in its ::ffff: form.
        var src = CaptureAddress(srcIp, dstIp);
        var dst = CaptureAddress(dstIp, srcIp);
        var ipv6 = src.AddressFamily == AddressFamily.InterNetworkV6;

        var ethHeader = BuildEthernetHeader(ipv6 ? (ushort)0x86DD : (ushort)0x0800);
        var ipHeader = ipv6
            ? BuildIpv6Header(src, dst, payload.Length)
            : BuildIpv4Header(src, dst, payload.Length);

        // TCP header (20 bytes)
        var tcpHeader = new byte[20];
        tcpHeader[0] = (byte)(srcPort >> 8); // Source port high
        tcpHeader[1] = (byte)(srcPort & 0xff); // Source port low
        tcpHeader[2] = (byte)(dstPort >> 8); // Destination port high
        tcpHeader[3] = (byte)(dstPort & 0xff); // Destination port low
        WriteBigEndian(tcpHeader, 4, seq); // Sequence number
        WriteBigEndian(tcpHeader, 8, ack); // Acknowledgment number
        tcpHeader[12] = 0x50; // Data offset (5 * 4 = 20 bytes)
        tcpHeader[13] = flags;
        tcpHeader[14] = 0xff; tcpHeader[15] = 0xff; // Window size
        // RFC 9293 §3.1 requires the field to cover the pseudo-header, the header and the data;
        // Wireshark validates it, so a placeholder marks every packet "Bad checksum".
        var tcpChecksum = ComputeTcpChecksum(src, dst, tcpHeader, payload);
        tcpHeader[16] = (byte)(tcpChecksum >> 8);
        tcpHeader[17] = (byte)tcpChecksum;
        tcpHeader[18] = 0x00; tcpHeader[19] = 0x00; // Urgent pointer

        // Combine all parts. An Ethernet frame is at least 64 octets including the 4-octet FCS, so a
        // bare 5-octet TLS record is zero-padded to 60: the padding is outside the IP total length, as
        // it is on a real wire, and Wireshark shows it as Ethernet padding rather than payload.
        var frameLength = ethHeader.Length + ipHeader.Length + tcpHeader.Length + payload.Length;
        var packet = new byte[Math.Max(frameLength, 60)];
        Array.Copy(ethHeader, 0, packet, 0, ethHeader.Length);
        Array.Copy(ipHeader, 0, packet, ethHeader.Length, ipHeader.Length);
        Array.Copy(tcpHeader, 0, packet, ethHeader.Length + ipHeader.Length, tcpHeader.Length);
        Array.Copy(payload, 0, packet, ethHeader.Length + ipHeader.Length + tcpHeader.Length, payload.Length);

        return packet;
    }

    private static IPAddress CaptureAddress(IPAddress self, IPAddress other)
    {
        if (self.AddressFamily == other.AddressFamily) return self;
        return self.AddressFamily == AddressFamily.InterNetwork ? self.MapToIPv6() : self;
    }

    private static byte[] BuildEthernetHeader(ushort etherType)
    {
        var header = new byte[14];
        // Destination MAC (broadcast for simplicity)
        header[0] = 0xff; header[1] = 0xff; header[2] = 0xff;
        header[3] = 0xff; header[4] = 0xff; header[5] = 0xff;
        // Source MAC
        header[6] = 0x00; header[7] = 0x11; header[8] = 0x22;
        header[9] = 0x33; header[10] = 0x44; header[11] = 0x55;
        header[12] = (byte)(etherType >> 8);
        header[13] = (byte)(etherType & 0xff);
        return header;
    }

    private byte[] BuildIpv4Header(IPAddress src, IPAddress dst, int payloadLength)
    {
        var header = new byte[20];
        var totalLength = (ushort)(20 + 20 + payloadLength);
        header[0] = 0x45; // Version (4) + IHL (5)
        header[1] = 0x00; // DSCP + ECN
        header[2] = (byte)(totalLength >> 8);
        header[3] = (byte)(totalLength & 0xff);
        header[4] = 0x00; header[5] = 0x01; // Identification
        header[6] = 0x00; header[7] = 0x00; // Flags + Fragment offset
        header[8] = 0x40; // TTL (64)
        header[9] = 0x06; // Protocol (TCP = 6)
        header[10] = 0x00; header[11] = 0x00; // Checksum (placeholder)

        Array.Copy(src.GetAddressBytes(), 0, header, 12, 4);
        Array.Copy(dst.GetAddressBytes(), 0, header, 16, 4);

        var checksum = CalculateChecksum(header);
        header[10] = (byte)(checksum >> 8);
        header[11] = (byte)(checksum & 0xff);
        return header;
    }

    /// <summary>
    /// A fixed 40-byte IPv6 header (RFC 8200 §3). Unlike v4 it carries no header checksum; the TCP
    /// checksum covers the v6 pseudo-header instead, which ComputeTcpChecksum builds.
    /// </summary>
    private static byte[] BuildIpv6Header(IPAddress src, IPAddress dst, int payloadLength)
    {
        var header = new byte[40];
        header[0] = 0x60; // Version (6) + traffic class 0 + flow label 0
        var totalLength = (ushort)(20 + payloadLength);
        header[4] = (byte)(totalLength >> 8); // Payload length (TCP header + payload)
        header[5] = (byte)(totalLength & 0xff);
        header[6] = 0x06; // Next header (TCP = 6)
        header[7] = 0x40; // Hop limit (64)
        Array.Copy(src.GetAddressBytes(), 0, header, 8, 16);
        Array.Copy(dst.GetAddressBytes(), 0, header, 24, 16);
        return header;
    }

    private static void WriteBigEndian(byte[] target, int offset, uint value)
    {
        target[offset] = (byte)(value >> 24);
        target[offset + 1] = (byte)(value >> 16);
        target[offset + 2] = (byte)(value >> 8);
        target[offset + 3] = (byte)value;
    }

    private static ushort CalculateChecksum(byte[] data) => Fold(AddBytes(0, data));

    private static ushort ComputeTcpChecksum(IPAddress src, IPAddress dst, byte[] tcpHeader, byte[] payload)
    {
        var tcpLength = tcpHeader.Length + payload.Length;
        uint sum;
        if (src.AddressFamily == AddressFamily.InterNetwork)
        {
            // RFC 9293 §3.1 figure 2: source, destination, one zero octet, protocol, TCP length.
            // RFC 791 §3.1 covers only the IPv4 header checksum, so the pseudo-header is TCP's.
            Span<byte> pseudo = stackalloc byte[12];
            src.GetAddressBytes().CopyTo(pseudo);
            dst.GetAddressBytes().CopyTo(pseudo[4..]);
            pseudo[9] = 6;
            pseudo[10] = (byte)(tcpLength >> 8);
            pseudo[11] = (byte)tcpLength;
            sum = AddBytes(0, pseudo);
        }
        else
        {
            // RFC 8200 §8.1: the same fields with 16-octet addresses and a 32-bit upper-layer length.
            Span<byte> pseudo = stackalloc byte[40];
            src.GetAddressBytes().CopyTo(pseudo);
            dst.GetAddressBytes().CopyTo(pseudo[16..]);
            pseudo[32] = (byte)(tcpLength >> 24);
            pseudo[33] = (byte)(tcpLength >> 16);
            pseudo[34] = (byte)(tcpLength >> 8);
            pseudo[35] = (byte)tcpLength;
            pseudo[39] = 6;
            sum = AddBytes(0, pseudo);
        }
        sum = AddBytes(sum, tcpHeader);   // checksum field still zero, as the sum requires
        sum = AddBytes(sum, payload);
        return Fold(sum);
    }

    // Ones' complement sum with end-around carry (RFC 1071 §1). Each part is summed separately, which
    // RFC 1071 §2 permits provided the even/odd byte assignment is respected. The pseudo-header and
    // TCP header are even-length, so an odd tail can only occur in the payload, which is summed last
    // and padded on the right as RFC 9293 §3.1 describes.
    private static uint AddBytes(uint sum, ReadOnlySpan<byte> data)
    {
        for (var i = 0; i + 1 < data.Length; i += 2)
            sum += (ushort)((data[i] << 8) | data[i + 1]);
        if ((data.Length & 1) != 0)
            sum += (uint)(data[^1] << 8);
        return sum;
    }

    private static ushort Fold(uint sum)
    {
        while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);
        return (ushort)~sum;
    }

    public void Dispose()
    {
        _writer.Flush();
        _writer.Dispose();
        _stream.Dispose();
        Console.WriteLine($"[PCAP] Wrote {_packetCount} packets");
    }
}

/// <summary>
/// Holds one client leg's handshake bytes until the handshake settles. A client that refuses the
/// flight otherwise leaves no record at all: a relay pcap is only opened after "MITM established",
/// so the hello, the chain that was rejected and any alert record are gone by the time the log line
/// is written. Recording stops as soon as the handshake succeeds, so relayed payload never piles up
/// here as well.
/// </summary>
public sealed class HandshakeCapture
{
    // A hello is a couple of kilobytes and a flight with a four-certificate chain stays under
    // 16 KiB; anything beyond that is application data arriving early, and this buffer has no
    // business holding it.
    private const int MaxBytes = 64 * 1024;

    private readonly List<(byte[] Data, bool FromClient)> _chunks = new();
    private int _total;
    private bool _settled;

    public void Record(ReadOnlySpan<byte> data, bool fromClient)
    {
        if (_settled || data.Length == 0 || _total >= MaxBytes) return;
        _chunks.Add((data.ToArray(), fromClient));
        _total += data.Length;
    }

    /// <summary>The handshake made it; the bytes are no longer evidence and the relay takes over.</summary>
    public void Stop()
    {
        _settled = true;
        _chunks.Clear();
        _total = 0;
    }

    /// <summary>
    /// Writes what was recorded as a capture of the aborted handshake. Each chunk keeps its own
    /// direction, so a reader sees the flow the two peers saw rather than one endless sender, and the
    /// hello, the flight and anything the client sent back line up in order.
    /// </summary>
    public void SaveAborted(string host, IPAddress clientIp, ushort clientPort,
        IPAddress serverIp, ushort serverPort)
    {
        if (_settled || _chunks.Count == 0) return;
        _settled = true;

        var safeHost = string.Join("_", host.Split(Path.GetInvalidFileNameChars()));
        var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var connectionId = Guid.NewGuid().ToString("N").Substring(0, 8);
        var pcapPath = $"captures/{safeHost}_{timestamp}_{connectionId}_aborted.pcap";
        var recorded = _total;

        try
        {
            Directory.CreateDirectory("captures");
            using var pcap = new PcapWriter(pcapPath);
            foreach (var (data, fromClient) in _chunks)
                pcap.WritePacket(data, fromClient,
                    fromClient ? clientIp : serverIp, fromClient ? serverIp : clientIp,
                    fromClient ? clientPort : serverPort, fromClient ? serverPort : clientPort);
            Console.WriteLine($"[Proxy] Aborted handshake for {host} saved to {pcapPath} ({recorded} bytes)");
        }
        catch (Exception ex)
        {
            // The handshake failure itself is already on the log; losing its evidence must not add a
            // second exception to the connection that is dying anyway.
            Console.WriteLine($"[Proxy] Handshake capture for {host} could not be saved: {ex.Message}");
        }
        _chunks.Clear();
    }
}
