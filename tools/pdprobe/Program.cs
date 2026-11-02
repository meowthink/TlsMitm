using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Router;

// Drives the product's own PdClient over one real interface, with no driver and no elevation, so the
// exchange that failed in a live run can be read message by message.
//
// usage: pdprobe <link-local> <ifIdx> [seconds] [iaid-as-hex]
// The IAID default is this probe's own number rather than Router's; pass a different one per interface when
// several links ask at the same time.
if (args.Length < 2)
{
    Console.WriteLine("usage: pdprobe <link-local> <ifIdx> [seconds] [iaid-as-hex]");
    return 2;
}

var linkLocal = IPAddress.Parse(args[0]);
var ifIdx = int.Parse(args[1]);
var seconds = args.Length > 2 ? int.Parse(args[2]) : 20;
var iaid = args.Length > 3 ? Convert.ToUInt32(args[3], 16) : 0x524F5636;

byte[]? mac = null;
foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
{
    try
    {
        if (nic.GetIPProperties().GetIPv6Properties().Index != ifIdx) continue;
        mac = nic.GetPhysicalAddress().GetAddressBytes();
        Console.WriteLine($"[probe] {nic.Name} ifIdx={ifIdx} mac={BitConverter.ToString(mac)}");
    }
    catch (NetworkInformationException)
    {
    }
}

if (mac is not { Length: 6 })
{
    Console.WriteLine($"[probe] no adapter reports IPv6 index {ifIdx}");
    return 2;
}

var pd = new PdClient(Dhcp6.DuidLl(mac), iaid, 60, Random.Shared.NextDouble);
using var udp = new UdpClient(AddressFamily.InterNetworkV6);
udp.Client.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, true);
udp.Client.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastLoopback, false);
udp.Client.Bind(new IPEndPoint(linkLocal, Dhcp6.ClientPort));
udp.Client.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.AddMembership,
    new IPv6MulticastOption(IPAddress.Parse(Dhcp6.AllRelayAgentsAndServers), ifIdx));
udp.Client.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastInterface, ifIdx);
Console.WriteLine($"[probe] bound {linkLocal}:{Dhcp6.ClientPort} on ifIdx {ifIdx}, state {pd.State}");

void Apply(IReadOnlyList<PdStep> steps)
{
    foreach (var step in steps)
    {
        switch (step)
        {
            case PdTransmit transmit:
                var destination = IPAddress.Parse(Dhcp6.AllRelayAgentsAndServers);
                var sent = udp.Send(transmit.Datagram, transmit.Datagram.Length,
                    new IPEndPoint(destination, Dhcp6.ServerPort));
                Console.WriteLine($"[probe] tx {transmit.Note} -> {destination}:{Dhcp6.ServerPort} " +
                                  $"({sent} octets, type {transmit.Datagram[0]}, " +
                                  $"xid {transmit.Datagram[1]:x2}{transmit.Datagram[2]:x2}{transmit.Datagram[3]:x2})");
                Console.WriteLine($"[probe]    {BitConverter.ToString(transmit.Datagram)}");
                break;
            case PdDelegated delegated:
                Console.WriteLine($"[probe] DELEGATED {delegated.Prefix} preferred " +
                                  $"{delegated.Preferred.TotalHours:0.#}h valid {delegated.Valid.TotalHours:0.#}h " +
                                  $"from {delegated.Server} dns {delegated.Dns.Count}");
                break;
            case PdWithdrawn withdrawn:
                Console.WriteLine($"[probe] WITHDRAWN {withdrawn.Prefix}: {withdrawn.Why}");
                break;
        }
    }
}

Apply(pd.Start(DateTime.UtcNow));
var deadline = DateTime.UtcNow.AddSeconds(seconds);
while (DateTime.UtcNow < deadline)
{
    var now = DateTime.UtcNow;
    Apply(pd.Poll(now));
    while (udp.Available > 0)
    {
        IPEndPoint from = new(IPAddress.IPv6Any, 0);
        var datagram = udp.Receive(ref from);
        Console.WriteLine($"[probe] rx {datagram.Length} octets from {from.Address}:" +
                          $"{from.Port} type {datagram[0]} xid " +
                          $"{datagram[1]:x2}{datagram[2]:x2}{datagram[3]:x2} options " +
                          $"{Dhcp6Message.TryParse(datagram, out var parsed, out var why)} {why}");
        Console.WriteLine($"[probe]    {BitConverter.ToString(datagram)}");
        if (parsed is not null)
            Console.WriteLine($"[probe]    parsed: kind {parsed.Kind}, {parsed.Describe()}");
        Apply(pd.Receive(datagram, from.Address, now));
    }
    Thread.Sleep(20);
}

Apply(pd.Release(DateTime.UtcNow));
while (udp.Available > 0)
{
    IPEndPoint from = new(IPAddress.IPv6Any, 0);
    var datagram = udp.Receive(ref from);
    Console.WriteLine($"[probe] rx after release {datagram.Length} octets type {datagram[0]}");
}
Console.WriteLine($"[probe] final state {pd.State}, prefix {(pd.Prefix is { } p ? p.ToString() : "none")}");
return 0;
