using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace TlsMitm;

[SupportedOSPlatform("windows")]
public static unsafe class WinDivertPInvoke
{
    private const string Lib = "WinDivert.dll";

    public const int MTU_MAX = 40 + 0xFFFF;
    public const int ADDR_SIZE = 80;

    // Header multi-byte fields are network byte order on the wire. The raw structs
    // expose them without conversion, so every read/write must go through these.
    public static ushort NetToHost(ushort value) => System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(value);
    public static ushort HostToNet(ushort value) => System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(value);

    public enum Layer : byte { Network = 0, Forward = 1, Flow = 2, Socket = 3, Reflect = 4 }

    [Flags]
    public enum Flag : ulong
    {
        None = 0,
        Sniff = 0x0001,
        Drop = 0x0002,
        RecvOnly = 0x0004,
        SendOnly = 0x0008,
        NoInstall = 0x0010,
        Fragments = 0x0020,
    }

    public enum ShutdownMode : int { Recv = 0, Send = 1, Both = 2 }

    [Flags]
    public enum AddressFlag : byte
    {
        None = 0,
        Sniffed = 0x1,
        Outbound = 0x2,
        Loopback = 0x4,
        Impostor = 0x8,
        IPv6 = 0x10,
        IPChecksum = 0x20,
        TCPChecksum = 0x40,
        UDPChecksum = 0x80,
    }

    [Flags]
    public enum ChecksumsFlag : ulong
    {
        All = 0,
        NoIpChecksum = 1,
        NoIcmpChecksum = 2,
        NoIcmpV6Checksum = 4,
        NoTcpChecksum = 8,
        NoUdpChecksum = 16,
    }

    [Flags]
    public enum TcpFlag : byte
    {
        Fin = 0x1,
        Syn = 0x2,
        Rst = 0x4,
        Psh = 0x8,
        Ack = 0x10,
        Urg = 0x20,
    }

    // WINDIVERT_ADDRESS: Timestamp(8) + Layer(1) + Event(1) + Flags(1) + Reserved(1) + Reserved2(4) + Union(64) = 80 bytes
    [StructLayout(LayoutKind.Explicit, Size = ADDR_SIZE)]
    public struct Address
    {
        [FieldOffset(0)] public long Timestamp;
        [FieldOffset(8)] public Layer Layer;
        [FieldOffset(9)] public byte Event;
        [FieldOffset(10)] public AddressFlag Flags;
        [FieldOffset(11)] public byte Reserved;
        [FieldOffset(12)] public uint Reserved2;
        [FieldOffset(16)] public int IfIdx;
        [FieldOffset(20)] public int SubIfIdx;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct NativeIpv4Header
    {
        public byte VersionAndIhl;
        public byte TOS;
        public ushort TotalLength;
        public ushort Id;
        public ushort FlagsAndFragOff;
        public byte TTL;
        public byte Protocol;
        public ushort Checksum;
        public uint SrcAddr;
        public uint DstAddr;

        public byte Ihl => (byte)(VersionAndIhl & 0x0F);
        public int HeaderLength => Ihl * 4;
        public byte Version => (byte)((VersionAndIhl >> 4) & 0x0F);
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct NativeIpv6Header
    {
        public byte Bitfield1;
        public byte Bitfield2;
        public ushort FlowLabel1;
        public ushort PayloadLength;
        public byte NextHeader;
        public byte HopLimit;
        public fixed byte SourceAddress[16];
        public fixed byte DestinationAddress[16];
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct NativeTcpHeader
    {
        public ushort SrcPort;
        public ushort DstPort;
        public uint SeqNum;
        public uint AckNum;
        public byte DataOffsetAndReserved;
        public TcpFlag Flags;
        public ushort Window;
        public ushort Checksum;
        public ushort UrgentPointer;

        public byte DataOffset => (byte)((DataOffsetAndReserved >> 4) & 0x0F);
        public int HeaderLength => DataOffset * 4;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct NativeUdpHeader
    {
        public ushort SrcPort;
        public ushort DstPort;
        public ushort Length;
        public ushort Checksum;
    }

    // P/Invoke declarations, signatures per WinDivert.h
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl, SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern IntPtr WinDivertOpen(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        Layer layer,
        short priority,
        Flag flags);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool WinDivertClose(IntPtr handle);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool WinDivertShutdown(IntPtr handle, ShutdownMode how);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool WinDivertRecvEx(
        IntPtr handle,
        void* pPacket,
        int packetLen,
        int* pRecvLen,
        ulong flags,
        Address* pAddr,
        int* pAddrLen,
        NativeOverlapped* lpOverlapped);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool WinDivertSendEx(
        IntPtr handle,
        void* pPacket,
        int packetLen,
        int* pSendLen,
        ulong flags,
        Address* pAddr,
        int addrLen,
        NativeOverlapped* lpOverlapped);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl, SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern bool WinDivertHelperCompileFilter(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        Layer layer,
        void* obj,
        int objLen,
        out IntPtr errorStr,
        out int errorPos);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool WinDivertHelperCalcChecksums(
        void* pPacket,
        int packetLen,
        Address* pAddr,
        ChecksumsFlag flags);

    // SOCKADDR_INET: matches Windows sockaddr_inet layout (28 bytes)
    [StructLayout(LayoutKind.Explicit, Size = 28)]
    public struct SockAddr
    {
        [FieldOffset(0)] public ushort Family;
        [FieldOffset(2)] public ushort Port;
        [FieldOffset(4)] public uint V4Addr;
        [FieldOffset(8)] public fixed byte V6Addr[16];
        [FieldOffset(24)] public uint V6ScopeId;

        public static SockAddr FromIPv4(uint addr)
        {
            SockAddr sa = default;
            sa.Family = 2; // AF_INET
            sa.V4Addr = addr;
            return sa;
        }

        public static SockAddr FromIPv6(byte* addrBytes)
        {
            SockAddr sa = default;
            sa.Family = 23; // AF_INET6
            for (int i = 0; i < 16; i++)
                sa.V6Addr[i] = addrBytes[i];
            return sa;
        }
    }

    // iphlpapi.dll P/Invoke for routing table lookups (CalcOutboundFlag)
    private const string IpHlpApi = "iphlpapi.dll";

    [DllImport(IpHlpApi, SetLastError = true)]
    public static extern int GetBestInterfaceEx(ref SockAddr dwDestAddr, out int dwBestIfIndex);

    [DllImport(IpHlpApi, SetLastError = true)]
    public static extern int GetBestRoute2(
        IntPtr interfaceLuid,
        int interfaceIndex,
        SockAddr* pSourceAddress,
        ref SockAddr destinationAddress,
        uint addressSortOptions,
        byte* pBestRoute,
        ref SockAddr bestSourceAddress);

    // Managed wrapper class
    public class WinDivertHandle : IDisposable
    {
        private IntPtr _handle;
        private bool _disposed;

        public IntPtr Handle => _handle;

        public WinDivertHandle(string filter, Layer layer = Layer.Network, short priority = 0, Flag flags = Flag.None)
        {
            if (layer != Layer.Network && flags == Flag.None)
                flags = Flag.Sniff | Flag.RecvOnly;

            var compiled = CompileFilter(filter, layer);
            _handle = WinDivertOpen(compiled, layer, priority, flags);
            if (_handle == IntPtr.Zero || _handle == new IntPtr(-1))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        public bool Recv(void* pPacket, int packetLen, int* pRecvLen, Address* pAddr)
        {
            return WinDivertRecvEx(_handle, pPacket, packetLen, pRecvLen, 0, pAddr, null, null);
        }

        public bool Send(void* pPacket, int packetLen, int* pSendLen, Address* pAddr)
        {
            return WinDivertSendEx(_handle, pPacket, packetLen, pSendLen, 0, pAddr, ADDR_SIZE, null);
        }

        public bool CalcChecksums(void* pPacket, int packetLen, Address* pAddr, ChecksumsFlag flags = ChecksumsFlag.All)
        {
            return WinDivertHelperCalcChecksums(pPacket, packetLen, pAddr, flags);
        }

        public bool Shutdown(ShutdownMode how = ShutdownMode.Both)
        {
            return WinDivertShutdown(_handle, how);
        }

        public unsafe bool CalcOutboundFlag(void* pPacket, Address* pAddr)
            => CalcOutboundFlag(pPacket, pAddr, out _);

        public unsafe bool CalcOutboundFlag(void* pPacket, Address* pAddr, out int routeErr)
        {
            routeErr = -1;
            var version = (*(byte*)pPacket >> 4) & 0x0F;
            uint srcAddr, dstAddr;
            byte* srcAddrV6 = null;
            byte* dstAddrV6 = null;
            bool isV6 = false;

            if (version == 4)
            {
                var ip4 = (NativeIpv4Header*)pPacket;
                srcAddr = ip4->SrcAddr;
                dstAddr = ip4->DstAddr;
            }
            else if (version == 6)
            {
                var ip6 = (NativeIpv6Header*)pPacket;
                srcAddrV6 = (byte*)ip6->SourceAddress;
                dstAddrV6 = (byte*)ip6->DestinationAddress;
                isV6 = true;
                srcAddr = 0;
                dstAddr = 0;
            }
            else
            {
                return false;
            }

            SockAddr dstSock, srcSock;
            if (isV6)
            {
                dstSock = SockAddr.FromIPv6(dstAddrV6);
                srcSock = SockAddr.FromIPv6(srcAddrV6);
            }
            else
            {
                dstSock = SockAddr.FromIPv4(dstAddr);
                srcSock = SockAddr.FromIPv4(srcAddr);
            }

            int ifIdx = pAddr->IfIdx;
            if (ifIdx == 0)
            {
                int err = GetBestInterfaceEx(ref dstSock, out ifIdx);
                if (err != 0)
                {
                    routeErr = err;
                    return false;
                }
            }

            byte* pBestRoute = stackalloc byte[103];
            SockAddr bestSrc = default;
            int errorCode = GetBestRoute2(IntPtr.Zero, ifIdx, &srcSock, ref dstSock, 0, pBestRoute, ref bestSrc);

            if (errorCode == 0)
                pAddr->Flags |= AddressFlag.Outbound;
            else
                pAddr->Flags &= ~AddressFlag.Outbound;

            routeErr = errorCode;
            return true;
        }

        public void Dispose()
        {
            if (!_disposed && _handle != IntPtr.Zero)
            {
                WinDivertClose(_handle);
                _handle = IntPtr.Zero;
                _disposed = true;
            }
        }

        private static string CompileFilter(string filter, Layer layer)
        {
            const int size = 4096;
            var obj = stackalloc byte[size];
            if (WinDivertHelperCompileFilter(filter, layer, obj, size, out var errStr, out var errPos))
            {
                return Marshal.PtrToStringAnsi(new IntPtr(obj)) ?? filter;
            }
            var msg = Marshal.PtrToStringAnsi(errStr) ?? "Unknown error";
            throw new FormatException($"Filter compile error: {msg}");
        }
    }

    // Driver auto-loader: the pair is unpacked next to the driver file and loaded by absolute
    // path, so neither a PATH entry nor the usual DLL search order is involved.
    static WinDivertPInvoke()
    {
        try { LoadDriver(); } catch { }
    }

    private static void LoadDriver()
    {
        // x64 only: this DLL runs inside the proxy process, not in the intercepted client, so a
        // 32-bit client is still captured - the filtering happens in the kernel driver.
        const string sysName = "WinDivert64.sys";
        const string dllName = "WinDivert.dll";

        var basePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "TlsMitm", "windivert-2.2.2", "x64");
        var sysPath = Path.Combine(basePath, sysName);
        var dllPath = Path.Combine(basePath, dllName);

        var asm = typeof(WinDivertPInvoke).Assembly;
        ExtractResource(asm, "TlsMitm.windivert.x64." + sysName, sysPath);
        ExtractResource(asm, "TlsMitm.windivert.x64." + dllName, dllPath);

        Kernel32.LoadLibrary(dllPath);
    }

    // Re-extracted when the embedded copy differs in length, so an upgrade never keeps running
    // against the driver left by an older build.
    private static void ExtractResource(System.Reflection.Assembly asm, string resourceName, string destPath)
    {
        using var stream = asm.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException($"{resourceName} is not embedded in this build");
        if (File.Exists(destPath) && new FileInfo(destPath).Length == stream.Length) return;
        Directory.CreateDirectory(Path.GetDirectoryName(destPath)!);
        using var fs = File.Create(destPath);
        stream.CopyTo(fs);
    }

    private static class Kernel32
    {
        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string path);
    }
}
