using System.Runtime.InteropServices;

namespace Router;

// The transport ports this host itself holds, read out of the same two tables netstat reads.
//
// Why the NAT has to know them: RFC 4787 REQ-1 makes the mapped port the whole reverse key, so a port this
// program hands to a LAN client's flow and a port one of this host's own sockets is bound to cannot both
// work - the reply leg's filter takes anything inbound to the WAN address at or above NatTable.PortFirst,
// which includes the answer a local socket is waiting for, and DNATs it to the client. The resolver's
// upstream socket is the standing case: `netsh int ipv4 show dynamicport tcp|udp` is 49152+16384 on this
// host, the same span as the NAT's pool, and that socket lives for the whole run.
//
// What this cannot fix: the host is free to bind a port the NAT handed out a second ago. The refresh
// interval bounds how long that state can last; it does not exclude it.
public sealed class LocalPorts
{
    // IANA protocol numbers, the same octet NatTable reads out of the IP header.
    public const byte Tcp = 6;
    public const byte Udp = 17;

    // The default is the interval the NAT's own sweep runs at, so the two clocks do not disagree about how
    // stale a read is.
    private static readonly TimeSpan DefaultTtl = TimeSpan.FromSeconds(5);

    private const int AfInet = 2;
    private const int TcpTableOwnerPidAll = 5;
    private const int UdpTableOwnerPid = 1;
    private const int ErrorInsufficientBuffer = 122;

    private readonly TimeSpan _ttl;
    private readonly Func<DateTime> _now;
    private readonly Func<byte, ICollection<ushort>> _read;
    private readonly object _gate = new();
    private DateTime _readAt = DateTime.MinValue;
    private HashSet<ushort> _tcp = new(), _udp = new();

    // The reader is a parameter because the refresh window is what keeps a port the host gave back from
    // being marked held for the rest of the run, and that is invisible from the wire.
    public LocalPorts(Func<byte, ICollection<ushort>>? reader = null, TimeSpan? ttl = null,
        Func<DateTime>? now = null)
    {
        _read = reader ?? Read;
        _ttl = ttl ?? DefaultTtl;
        _now = now ?? (() => DateTime.UtcNow);
    }

    /// Ports the host holds for one IANA protocol number. Anything that is not TCP or UDP has no port to
    /// hold, and an empty set is what lets the allocator keep its own rule for those.
    public ICollection<ushort> Held(byte proto)
    {
        if (proto != Tcp && proto != Udp) return Array.Empty<ushort>();
        lock (_gate)
        {
            if (_now() - _readAt < _ttl) return proto == Tcp ? _tcp : _udp;
            _readAt = _now();
            // Both tables are read together so one refresh costs one pair of calls however often the
            // allocator asks, and a read that fails yields an empty set: excluding nothing leaves the run
            // exactly as it was before this existed, which beats refusing to forward.
            _tcp = ToSet(_read(Tcp));
            _udp = ToSet(_read(Udp));
            return proto == Tcp ? _tcp : _udp;
        }
    }

    private static HashSet<ushort> ToSet(ICollection<ushort> ports) => new(ports);

    private static HashSet<ushort> Read(byte proto)
    {
        var udp = proto == Udp;
        // MIB_UDPROW_OWNER_PID is localAddr, localPort, owningPid; MIB_TCPROW_OWNER_PID adds state and the
        // remote pair in front of the pid. Both tables put the row count in the DWORD before the first row.
        // Measured on this host: with these two sizes the UDP set is the same 17 ports `netstat -ano -p UDP`
        // lists, and any other row size makes them stop lining up after the first few.
        var rowSize = udp ? 12 : 24;
        var portOffset = udp ? 4 : 8;

        var ports = new HashSet<ushort>();
        var size = 1 << 16;
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            int rc;
            while (true)
            {
                rc = udp
                    ? GetExtendedUdpTable(buffer, ref size, false, AfInet, UdpTableOwnerPid, 0)
                    : GetExtendedTcpTable(buffer, ref size, false, AfInet, TcpTableOwnerPidAll, 0);
                if (rc != ErrorInsufficientBuffer) break;
                Marshal.FreeHGlobal(buffer);
                buffer = Marshal.AllocHGlobal(size);
            }
            if (rc == 0)
            {
                var rows = Marshal.ReadInt32(buffer);
                for (var i = 0; i < rows; i++)
                {
                    // The port DWORD carries the value in network byte order in its low two octets.
                    var raw = (uint)Marshal.ReadInt32(buffer, 4 + i * rowSize + portOffset);
                    ports.Add((ushort)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF)));
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        return ports;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedTcpTable(IntPtr tcpTable, ref int size, bool order,
        int addressFamily, int tableClass, int reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedUdpTable(IntPtr udpTable, ref int size, bool order,
        int addressFamily, int tableClass, int reserved);
}
