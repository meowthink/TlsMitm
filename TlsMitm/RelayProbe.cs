using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;

namespace TlsMitm;

/// <summary>
/// The SYN the relay's inbound reachability is judged with, and the reading that answers it.
///
/// Nothing in the firewall's rule store answers "will this host accept an inbound connection to the
/// relay port from a remote address": pre-defined service rules report their port field as a wildcard
/// while the condition lives in the filter, and an explicit block rule outranks an allow rule however
/// narrow the allow is (Windows Firewall with Advanced Security, "Rule precedence for inbound and
/// outbound rules"). A packet has no such ambiguity - either the listener answers it or it does not -
/// so this is what decides, and it is sent through the same injection a real client's packet goes
/// through.
///
/// The answer is read from the TCP table rather than from the proxy's accept queue. RFC 9293 §3.5
/// Figure 6 puts the receiving peer in SYN-RECEIVED on the SYN alone (line 2) and in ESTABLISHED only on
/// the acknowledgment of the SYN,ACK (line 4), and this probe is that lone SYN: it never completes a
/// handshake, so nothing is handed to the accept queue either way. What the stack does leave for a SYN it
/// passed to a listener is the SYN-RECEIVED row, and that row is the observable.
/// </summary>
public static class RelayProbe
{
    public const int Length = 40;

    /// shared/tcpmib.h, `MIB_TCP_STATE`: the state a listener's table row carries for a SYN it has
    /// answered but not completed. Read out of the installed header, not inferred from the order.
    public const uint SynRcvd = 4;

    public const int RowLength = 20;

    /// The IPv4 and TCP header fields in wire order. The two checksum fields stay zero: the driver's
    /// CalcChecksums fills them on the way in, which is why no caller of this has to know the pseudo
    /// header.
    public static byte[] BuildSyn(IPAddress source, IPAddress destination, ushort sourcePort, ushort destinationPort)
    {
        var packet = new byte[Length];
        packet[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), Length);
        packet[8] = 64;
        packet[9] = 6;
        source.GetAddressBytes().CopyTo(packet, 12);
        destination.GetAddressBytes().CopyTo(packet, 16);

        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(20, 2), sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(22, 2), destinationPort);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(24, 4), 0x11223344);
        // The header's own length lives in the byte before the flags, and a packet that leaves it at zero
        // carries a TCP header the stack reads as absent. RFC 9293 §3.1 puts the Data Offset there, in
        // units of 32-bit words, so 20 bytes of header is 5.
        packet[32] = 0x50;
        packet[33] = 0x02;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(34, 2), 64240);
        return packet;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetTcpTable(nint tcpTable, ref uint sizePointer, bool order);

    /// The IPv4 connection table as the stack publishes it: a row count and then that many 20-octet rows.
    /// Null when the table could not be read, which the caller reports as "unknown" rather than "filtered".
    public static byte[]? ReadTcpTable()
    {
        uint size = 0;
        GetTcpTable(0, ref size, false); // the size query fails and fills in what is needed
        if (size < 4) return null;
        var buffer = Marshal.AllocHGlobal((int)size);
        try
        {
            if (GetTcpTable(buffer, ref size, false) != 0) return null;
            var table = new byte[size];
            Marshal.Copy(buffer, table, 0, (int)size);
            return table;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// Whether this table holds the row a probe of <paramref name="token"/> put in front of a listener.
    /// All four fields have to agree, because a row from any other peer or port says nothing about this
    /// packet.
    ///
    /// The field order is shared/tcpmib.h's `MIB_TCPROW`: state, local address, local port, remote
    /// address, remote port, each a DWORD. The two port members are decoded big-endian - measured against
    /// `netstat -ano -p tcp` on this host, where the same bytes read this way give 443 and 80 - and the
    /// addresses are the octets in wire order, so they go straight into an IPAddress.
    public static bool Answers(ReadOnlySpan<byte> table, IPAddress probeSource, ushort token,
        IPAddress lanAddress, ushort relayPort)
    {
        if (table.Length < 4) return false;
        var rows = BinaryPrimitives.ReadUInt32LittleEndian(table);
        // A count larger than the bytes that came back is a table that changed shape under the read; the
        // rows that are physically there are all that can be judged.
        var whole = (uint)((table.Length - 4) / RowLength);
        if (rows > whole) rows = whole;
        for (var row = 0; row < rows; row++)
        {
            var fields = table.Slice(4 + row * RowLength, RowLength);
            if (BinaryPrimitives.ReadUInt32LittleEndian(fields) != SynRcvd) continue;
            if (!new IPAddress(fields.Slice(4, 4)).Equals(lanAddress)) continue;
            if (BinaryPrimitives.ReadUInt16BigEndian(fields.Slice(8, 2)) != relayPort) continue;
            if (!new IPAddress(fields.Slice(12, 4)).Equals(probeSource)) continue;
            if (BinaryPrimitives.ReadUInt16BigEndian(fields.Slice(16, 2)) != token) continue;
            return true;
        }

        return false;
    }
}
