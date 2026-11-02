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
/// instead, on the interface the client is attached to. The same side seen in IPv6 is carried beside
/// it, because one interface can hold both families and one capture leg serves both.
/// </summary>
public sealed record LanSide(IPAddress Address, IPAddress Network, IPAddress Last, int IfIdx, LanSideV6? V6 = null)
{
    public uint RawAddress => ToRaw(Address);

    // A forwarded packet still carries the client's own source address, and inside this subnet that is
    // the only field separating the LAN's traffic from anything else the host might route: at this
    // layer the interface index is the egress - measured, the transit packets arrive with the outbound
    // bit set and the WAN interface's index - so an index cannot name the LAN side.
    private string WithinSubnet => V6 is { } six
        ? $"not impostor and ((ip and ip.SrcAddr >= {Network} and ip.SrcAddr <= {Last})" +
          $" or (ipv6 and ipv6.SrcAddr >= {six.Network} and ipv6.SrcAddr <= {six.Last}))"
        : $"ip and not impostor and ip.SrcAddr >= {Network} and ip.SrcAddr <= {Last}";

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

/// <summary>
/// The IPv6 half of a LAN side. Its address is what a rewritten v6 packet is re-addressed to, and its
/// subnet is what the capture filter is bounded to, exactly as the IPv4 half is - the filter has to be
/// bounded because at the forward layer it is the only thing that keeps this process off traffic that
/// is not the LAN's. The WAN is never a member: a client of this LAN gets an address out of the prefix
/// the delegation installed, and nothing else is asked to leave through this host.
/// </summary>
public sealed record LanSideV6(IPAddress Address, IPAddress Network, IPAddress Last, int IfIdx)
{
    // The two words the rewrite writes into a v6 header, read the same way FlowState reads them, so the
    // address that goes on the wire is the one this side resolved.
    public (ulong Hi, ulong Lo) Raw
    {
        get
        {
            var bytes = Address.GetAddressBytes();
            return (BitConverter.ToUInt64(bytes, 0), BitConverter.ToUInt64(bytes, 8));
        }
    }

    public static LanSideV6? Resolve(string text)
    {
        if (!IPAddress.TryParse(text, out var address) || address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            Console.WriteLine($"[Main] --lan6 {text} is not an IPv6 address");
            return null;
        }

        var found = new List<LanSideV6>();
        var candidates = new List<string>();
        foreach (var unicast in GlobalV6())
        {
            candidates.Add($"{unicast.Address}/{unicast.PrefixLength} ifIdx={unicast.IfIdx} ({unicast.Nic})");
            if (!unicast.Address.Equals(address)) continue;
            var network = NetworkOf(address, unicast.PrefixLength);
            found.Add(new LanSideV6(address, network, LastOf(network, unicast.PrefixLength), unicast.IfIdx));
        }

        if (found.Count == 1) return found[0];

        Console.WriteLine(found.Count == 0
            ? $"[Main] --lan6 {text} is not a global address of a connected interface."
            : $"[Main] --lan6 {text} is an address of more than one connected interface.");
        foreach (var candidate in candidates) Console.WriteLine($"[Main]   {candidate}");
        return null;
    }

    /// The first IPv6 address the interface <paramref name="ifIdx"/> holds that a forwarded client could
    /// be delivered to. Used only to say, at startup, that a v6-capable interface is being left alone
    /// because <c>--lan6</c> was not given: without that line the run is silent about the whole family.
    public static IPAddress? HeldOn(int ifIdx) =>
        GlobalV6().Where(unicast => unicast.IfIdx == ifIdx).Select(unicast => unicast.Address).FirstOrDefault();

    // Link-local and multicast are left out: a forwarded packet is never delivered to either, and a
    // link-local carries its zone in the text form, which no filter literal would accept.
    private static List<(IPAddress Address, int PrefixLength, int IfIdx, string Nic)> GlobalV6()
    {
        var found = new List<(IPAddress Address, int PrefixLength, int IfIdx, string Nic)>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            // Same guard as the IPv4 walk: the properties for a family the adapter does not carry throw.
            if (!nic.Supports(NetworkInterfaceComponent.IPv6)) continue;
            var properties = nic.GetIPProperties();
            var ifIdx = properties.GetIPv6Properties()?.Index ?? 0;
            if (ifIdx <= 0) continue;
            foreach (var unicast in properties.UnicastAddresses)
            {
                if (unicast.Address.AddressFamily != AddressFamily.InterNetworkV6) continue;
                if (unicast.Address.IsIPv6LinkLocal || unicast.Address.IsIPv6Multicast) continue;
                found.Add((unicast.Address, unicast.PrefixLength, ifIdx, nic.Name));
            }
        }
        return found;
    }

    /// The address and the two bounds are counted in the address's own order, octet by octet: a v6
    /// address does not fit the uint the IPv4 half reads header fields as, and a borrow there would
    /// take the first octet instead of the last.
    public static IPAddress NetworkOf(IPAddress address, int prefixLength)
    {
        var bytes = address.GetAddressBytes();
        for (var i = 0; i < bytes.Length; i++)
        {
            var bits = Math.Clamp(prefixLength - i * 8, 0, 8);
            // The octets' own order, and the top `bits` of the byte are the prefix: a shift by 8-bits
            // leaves 0xFF for a whole octet and 0 for none of it.
            bytes[i] &= (byte)(0xFF << (8 - bits));
        }
        return new IPAddress(bytes);
    }

    /// The last address of the subnet, which is the filter's upper bound. IPv6 has no broadcast address,
    /// so unlike the IPv4 half this one is only a bound and is never handed out.
    public static IPAddress LastOf(IPAddress network, int prefixLength)
    {
        var bytes = network.GetAddressBytes();
        for (var i = 0; i < bytes.Length; i++)
        {
            var bits = Math.Clamp(prefixLength - i * 8, 0, 8);
            bytes[i] |= (byte)(0xFF >> bits);
        }
        return new IPAddress(bytes);
    }
}
