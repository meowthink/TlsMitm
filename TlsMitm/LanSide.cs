using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Numerics;

namespace TlsMitm;

/// <summary>
/// The LAN side a forwarded client arrives on, resolved from the address <c>--lan</c> names. Its
/// address is what a rewritten forwarded packet is re-addressed to: a client that is not on this
/// machine cannot be the destination of a local socket, so the packet is made to arrive at this host
/// instead, on the interface the client is attached to.
/// </summary>
public sealed record LanSide(IPAddress Address, IPAddress Network, IPAddress Last, int IfIdx)
{
    public uint RawAddress => ToRaw(Address);

    // A forwarded packet still carries the client's own source address, and inside this subnet that is
    // the only field separating the LAN's traffic from anything else the host might route: at this
    // layer the interface index is the egress - measured, the transit packets arrive with the outbound
    // bit set and the WAN interface's index - so an index cannot name the LAN side.
    private string WithinSubnet =>
        $"ip and not impostor and ip.SrcAddr >= {Network} and ip.SrcAddr <= {Last}";

    public string TcpFilter => $"tcp and {WithinSubnet}";

    // The same bounds for the UDP leg, so a client that prefers HTTP/3 is stopped from reaching a QUIC
    // server at all and has to fall back to the TCP this process does intercept.
    public string UdpFilter => $"udp and {WithinSubnet}";

    public static LanSide? Resolve(string text)
    {
        if (!IPAddress.TryParse(text, out var address) || address.AddressFamily != AddressFamily.InterNetwork)
        {
            Console.WriteLine($"[Main] --lan {text} is not an IPv4 address");
            return null;
        }

        var found = new List<LanSide>();
        var candidates = new List<string>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            // GetIPv4Properties throws 10043 on an adapter with no IPv4 bound (a v6-only tunnel is
            // one on this host), so the component has to be checked before asking.
            if (!nic.Supports(NetworkInterfaceComponent.IPv4)) continue;
            var properties = nic.GetIPProperties();
            var ifIdx = properties.GetIPv4Properties()?.Index ?? 0;
            if (ifIdx <= 0) continue;
            foreach (var unicast in properties.UnicastAddresses)
            {
                // An IPv6 entry answers IPv4Mask with a zero mask rather than null, so the family has
                // to be checked before the mask can mean anything.
                if (unicast.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                if (unicast.IPv4Mask is null) continue;
                var raw = ToRaw(unicast.Address);
                var mask = ToRaw(unicast.IPv4Mask);
                candidates.Add($"{unicast.Address}/{BitOperations.PopCount(mask)} ifIdx={ifIdx} ({nic.Name})");
                if (unicast.Address.Equals(address))
                    found.Add(new LanSide(address, FromRaw(raw & mask), FromRaw(raw | ~mask), ifIdx));
            }
        }

        if (found.Count == 1) return found[0];

        Console.WriteLine(found.Count == 0
            ? $"[Main] --lan {text} is not an address of a connected interface."
            : $"[Main] --lan {text} is an address of more than one connected interface.");
        foreach (var candidate in candidates) Console.WriteLine($"[Main]   {candidate}");
        return null;
    }

    // The uint form is the one the header fields are read as, so the round trip through the octets is
    // the only conversion that keeps the two comparable however the machine orders a uint.
    private static uint ToRaw(IPAddress address) => BitConverter.ToUInt32(address.GetAddressBytes());

    private static IPAddress FromRaw(uint value) => new(BitConverter.GetBytes(value));

    /// The source address the relay's inbound probe carries: one below this subnet's last address, which
    /// is its broadcast address, so the probe comes from a host address inside the subnet that no pool
    /// handed out from the low end reaches. It is not this host's address and not loopback, which is what
    /// makes its arrival a test of the inbound filter rather than of the local one.
    public IPAddress ProbeAddress
    {
        get
        {
            // Counted in the addresses' own order, not in the uint the header fields use: that one reads
            // the octets little-endian, so subtracting from it would take the first octet, not the last.
            Span<byte> big = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(big,
                unchecked(BinaryPrimitives.ReadUInt32BigEndian(Last.GetAddressBytes()) - 1u));
            return new IPAddress(big);
        }
    }
}
