using static TlsMitm.WinDivertPInvoke;

namespace TlsMitm;

// The address/port rewrite the redirector applies to an intercepted packet, separated from the WinDivert
// address fields, the checksum and the send so it can be judged on crafted packets offline. The caller
// keeps everything that needs the driver; these only touch the header bytes. The forward leg turns the
// client's packet into one the original server sends to this host's relay; the reverse leg turns the
// relay's answer back into the pair the client believes it opened.
internal static unsafe class PacketRewrite
{
    internal static (ulong Hi, ulong Lo) ReadV6(byte* addr) =>
        (BitConverter.ToUInt64(new ReadOnlySpan<byte>(addr, 8)), BitConverter.ToUInt64(new ReadOnlySpan<byte>(addr + 8, 8)));

    internal static void WriteV6(byte* addr, ulong hi, ulong lo)
    {
        BitConverter.TryWriteBytes(new Span<byte>(addr, 8), hi);
        BitConverter.TryWriteBytes(new Span<byte>(addr + 8, 8), lo);
    }

    internal static void ForwardV4(NativeIpv4Header* ip4, NativeTcpHeader* tcp,
        uint origDstAddr, uint localEndpoint, ushort token, ushort relayPort, bool loopback)
    {
        tcp->SrcPort = HostToNet(token);
        tcp->DstPort = HostToNet(relayPort);
        if (!loopback)
        {
            ip4->SrcAddr = origDstAddr;
            ip4->DstAddr = localEndpoint;
        }
    }

    internal static void ReverseV4(NativeIpv4Header* ip4, NativeTcpHeader* tcp,
        uint serverAddr, uint clientRaw, ushort origDstPort, ushort clientPort, bool loopback)
    {
        if (!loopback)
        {
            ip4->SrcAddr = serverAddr;
            ip4->DstAddr = clientRaw;
        }
        tcp->SrcPort = HostToNet(origDstPort);
        tcp->DstPort = HostToNet(clientPort);
    }

    internal static void ForwardV6(NativeIpv6Header* ip6, NativeTcpHeader* tcp,
        ulong serverHi, ulong serverLo, ulong deliverHi, ulong deliverLo,
        ushort token, ushort relayPort, bool loopback)
    {
        tcp->SrcPort = HostToNet(token);
        tcp->DstPort = HostToNet(relayPort);
        if (!loopback)
        {
            WriteV6(ip6->SourceAddress, serverHi, serverLo);
            WriteV6(ip6->DestinationAddress, deliverHi, deliverLo);
        }
    }

    internal static void ReverseV6(NativeIpv6Header* ip6, NativeTcpHeader* tcp,
        ulong serverHi, ulong serverLo, ulong clientHi, ulong clientLo,
        ushort origDstPort, ushort clientPort, bool loopback)
    {
        if (!loopback)
        {
            WriteV6(ip6->SourceAddress, serverHi, serverLo);
            WriteV6(ip6->DestinationAddress, clientHi, clientLo);
        }
        tcp->SrcPort = HostToNet(origDstPort);
        tcp->DstPort = HostToNet(clientPort);
    }
}
