using static TlsMitm.WinDivertPInvoke;

namespace TlsMitm;

/// <summary>
/// Recognises the opening of a QUIC long-header packet, which is what a QUIC handshake has to start
/// with (RFC 9000 §17.2: Header Form = 1, Fixed Bit = 1, then the four-byte Version).
/// </summary>
internal static unsafe class QuicSignature
{
    public static bool IsQuicDatagram(byte* packet, int recvLen, out ushort dstPort)
    {
        dstPort = 0;

        NativeUdpHeader* udp;
        int headerLen;
        if ((*packet >> 4) == 4)
        {
            var ip4 = (NativeIpv4Header*)packet;
            if (ip4->Protocol != 17) return false;
            headerLen = ip4->HeaderLength;
            if (recvLen < headerLen + sizeof(NativeUdpHeader)) return false;
            udp = (NativeUdpHeader*)(packet + headerLen);
        }
        else if ((*packet >> 4) == 6 && recvLen >= sizeof(NativeIpv6Header))
        {
            if (((NativeIpv6Header*)packet)->NextHeader != 17) return false;
            headerLen = sizeof(NativeIpv6Header);
            if (recvLen < headerLen + sizeof(NativeUdpHeader)) return false;
            udp = (NativeUdpHeader*)(packet + headerLen);
        }
        else return false;

        dstPort = WinDivertPInvoke.NetToHost(udp->DstPort);
        var payload = (byte*)udp + sizeof(NativeUdpHeader);
        return IsQuicPacket(payload, recvLen - headerLen - sizeof(NativeUdpHeader));
    }

    public static bool IsQuicPacket(byte* payload, int payloadLen)
    {
        if (payloadLen < 5) return false;

        // A long header sets Header Form (0x80) and Fixed Bit (0x40), and the next four bytes are the
        // Version (RFC 9000 §17.2). Version 1 is RFC 9000 §15 and version 2 is RFC 9369: the two a
        // browser offers. Anything else is left alone, because other UDP protocols also start with
        // bytes that can have those two bits set.
        if ((payload[0] & 0xC0) != 0xC0) return false;
        var version = (uint)((payload[1] << 24) | (payload[2] << 16) | (payload[3] << 8) | payload[4]);
        return version is 0x00000001 or 0x6b3343cf;
    }
}
