using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace TlsMitm;

/// <summary>
/// Which store the client will verify a forged leaf against. There is no universal chain: Chromium
/// (and any Schannel client) trusts the Windows store, which holds only the Fiddler root, while
/// Node/Electron verify against the Mozilla list bundled into their binary, which holds the emSign
/// roots and not the Fiddler one.
/// </summary>
public enum ClientTrust
{
    WindowsStore,
    NodeBundled
}

/// <param name="Ambiguous">
/// True when the process itself does not settle the question - an Electron main process runs Node's
/// TLS stack and Chromium's networking code in one binary, so a single connection still has to be
/// told apart by its ClientHello (Chromium sends GREASE, Node does not).
/// </param>
public readonly record struct ClientIdentity(ClientTrust Trust, int Pid, string Label, bool Ambiguous);

/// <summary>
/// Names the process that owns a client connection. The redirector hands the proxy the client's own
/// address and ephemeral port (as the accepted socket's local side and remote port), so the owning
/// PID comes straight out of the OS TCP table, and the command line tells Chromium's network service
/// apart from an Electron main process - both are the same executable.
/// </summary>
public static class ClientProcess
{
    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const int ERROR_INSUFFICIENT_BUFFER = 122;

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint PROCESS_VM_READ = 0x0010;

    private static readonly TimeSpan RowTtl = TimeSpan.FromMilliseconds(200);
    private static readonly TimeSpan PidTtl = TimeSpan.FromSeconds(10);

    private static readonly object RowGate = new();
    private static Dictionary<(IPAddress, int), int>? _rows;
    private static long _rowsTicks;

    private static readonly ConcurrentDictionary<int, (ClientIdentity Identity, long ExpiresTicks)> PidCache = new();

    public static ClientIdentity Identify(IPAddress clientAddress, int clientPort, out bool firstSighting)
    {
        firstSighting = false;
        var pid = LookupPid(clientAddress, clientPort);
        if (pid <= 0)
        {
            // A socket that completed its handshake after the last snapshot is absent from it, so a
            // miss has to re-read the table: otherwise a connection opened inside the cache window
            // silently gets the Windows chain, which a Node client then rejects.
            pid = LookupPid(clientAddress, clientPort, forceRefresh: true);
        }
        if (pid <= 0)
        {
            // Still unknown means the process is gone or inaccessible. Surface it instead of falling
            // back silently; this is the one path where the chain choice is a guess.
            firstSighting = true;
            return new ClientIdentity(ClientTrust.WindowsStore, 0, "unknown (no TCP owner)", false);
        }

        var now = Environment.TickCount64;
        if (PidCache.TryGetValue(pid, out var hit) && now < hit.ExpiresTicks)
            return hit.Identity;

        var imagePath = QueryImagePath(pid);
        var commandLine = QueryCommandLine(pid);
        var identity = Classify(pid, imagePath, commandLine);
        PidCache[pid] = (identity, now + (long)PidTtl.TotalMilliseconds);
        firstSighting = true;
        return identity;
    }

    private static ClientIdentity Classify(int pid, string? imagePath, string? commandLine)
    {
        var exe = imagePath == null ? $"pid {pid}" : Path.GetFileName(imagePath);
        var cmd = commandLine ?? "";

        // Electron's utilityProcess API runs Node in a --type=utility child; that child verifies with
        // the bundled list, unlike every other Chromium child.
        if (cmd.Contains("node.mojom.NodeService", StringComparison.OrdinalIgnoreCase))
            return new ClientIdentity(ClientTrust.NodeBundled, pid, $"{exe} (electron node service)", false);

        // Renderers, GPU and the network service all reach TLS through Schannel; the network service
        // is the one that carries page traffic.
        if (cmd.Contains("--type=", StringComparison.OrdinalIgnoreCase))
            return new ClientIdentity(ClientTrust.WindowsStore, pid, $"{exe} (chromium child)", false);

        if (string.Equals(exe, "node.exe", StringComparison.OrdinalIgnoreCase))
            return new ClientIdentity(ClientTrust.NodeBundled, pid, "node.exe", true);

        // A packaged Electron app spawns its own Node children as "app.exe <script>.mjs <args>". That
        // argv has no --type=, so without this it would be logged as the main process even though it
        // is a separate process on the same bundled-store TLS stack.
        if (RunsNodeScript(cmd))
            return new ClientIdentity(ClientTrust.NodeBundled, pid, $"{exe} (electron node worker)", true);

        // An Electron main process has no --type= and verifies with its bundled list; the .asar
        // beside the executable is what distinguishes it from a Chromium browser process, which
        // does not run Node and whose own connections go through its network service child.
        if (LooksLikeElectronApp(imagePath))
            return new ClientIdentity(ClientTrust.NodeBundled, pid, $"{exe} (electron main)", true);

        return new ClientIdentity(ClientTrust.WindowsStore, pid, $"{exe} (no known bundling)", false);
    }

    private static bool RunsNodeScript(string commandLine)
    {
        var exeEnd = commandLine.IndexOf('"');
        if (exeEnd < 0) return false;
        exeEnd = commandLine.IndexOf('"', exeEnd + 1);
        if (exeEnd < 0) return false;

        foreach (var token in commandLine[(exeEnd + 1)..].Split(['"', ' '], StringSplitOptions.RemoveEmptyEntries))
        {
            var arg = token.Trim();
            if (arg.Length == 0 || arg.StartsWith('-')) continue;
            if (arg.EndsWith(".js", StringComparison.OrdinalIgnoreCase)
                || arg.EndsWith(".mjs", StringComparison.OrdinalIgnoreCase)
                || arg.EndsWith(".cjs", StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static bool LooksLikeElectronApp(string? imagePath)
    {
        var dir = imagePath == null ? null : Path.GetDirectoryName(imagePath);
        if (dir == null) return false;
        var resources = Path.Combine(dir, "resources");
        return File.Exists(Path.Combine(resources, "app.asar"))
            || File.Exists(Path.Combine(resources, "electron.asar"))
            || File.Exists(Path.Combine(resources, "default_app.asar"));
    }

    private static int LookupPid(IPAddress address, int port, bool forceRefresh = false)
    {
        Dictionary<(IPAddress, int), int> rows;
        lock (RowGate)
        {
            if (forceRefresh || _rows == null
                || Environment.TickCount64 - _rowsTicks > (long)RowTtl.TotalMilliseconds)
            {
                _rows = ReadTcpTable();
                _rowsTicks = Environment.TickCount64;
            }
            rows = _rows;
        }

        return Find(rows, address, port);
    }

    private static int Find(Dictionary<(IPAddress, int), int> rows, IPAddress address, int port)
    {
        if (rows.TryGetValue((address, port), out var pid)) return pid;
        if (address.IsIPv4MappedToIPv6 && rows.TryGetValue((address.MapToIPv4(), port), out pid)) return pid;

        // A link-local v6 address carries a scope id that the TCP table does not repeat, and
        // IPAddress equality includes it; compare the 16 address bytes as a fallback.
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            var want = address.GetAddressBytes();
            foreach (var (key, owner) in rows)
            {
                if (key.Item2 != port || key.Item1.AddressFamily != address.AddressFamily) continue;
                if (key.Item1.GetAddressBytes().AsSpan().SequenceEqual(want)) return owner;
            }
        }
        return 0;
    }

    private static Dictionary<(IPAddress, int), int> ReadTcpTable()
    {
        var map = new Dictionary<(IPAddress, int), int>();
        ReadTable(AF_INET, map);
        ReadTable(AF_INET6, map);
        return map;
    }

    private static void ReadTable(int family, Dictionary<(IPAddress, int), int> map)
    {
        var size = 1 << 20;
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            while (true)
            {
                var rc = GetExtendedTcpTable(buffer, ref size, false, family, TCP_TABLE_OWNER_PID_ALL, 0);
                if (rc == ERROR_INSUFFICIENT_BUFFER)
                {
                    Marshal.FreeHGlobal(buffer);
                    buffer = Marshal.AllocHGlobal(size);
                    continue;
                }
                if (rc != 0) return;
                break;
            }

            var count = Marshal.ReadInt32(buffer);
            if (family == AF_INET)
            {
                // MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr, remotePort, pid.
                const int rowSize = 24;
                for (var i = 0; i < count; i++)
                {
                    var row = buffer + 4 + i * rowSize;
                    var pid = Marshal.ReadInt32(row, 20);
                    if (pid <= 0) continue;
                    var ip = new IPAddress((uint)Marshal.ReadInt32(row, 4));
                    map[(ip, ReadPort(row, 8))] = pid;
                }
            }
            else
            {
                // MIB_TCP6ROW_OWNER_PID: localAddr[16], localScopeId, localPort, remoteAddr[16],
                // remoteScopeId, remotePort, state, pid.
                const int rowSize = 56;
                for (var i = 0; i < count; i++)
                {
                    var row = buffer + 4 + i * rowSize;
                    var pid = Marshal.ReadInt32(row, 52);
                    if (pid <= 0) continue;
                    var bytes = new byte[16];
                    Marshal.Copy(row, bytes, 0, 16);
                    var ip = new IPAddress(bytes);
                    map[(ip, ReadPort(row, 20))] = pid;
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static int ReadPort(IntPtr row, int offset)
    {
        // dwLocalPort holds the port in network byte order in its low 16 bits.
        var raw = (uint)Marshal.ReadInt32(row, offset);
        return (int)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));
    }

    private static string? QueryImagePath(int pid)
    {
        var handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (handle == IntPtr.Zero) return null;
        try
        {
            var sb = new StringBuilder(1024);
            var len = sb.Capacity;
            return QueryFullProcessImageNameW(handle, 0, sb, ref len) ? sb.ToString() : null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private static string? QueryCommandLine(int pid)
    {
        var handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, pid);
        if (handle == IntPtr.Zero) return null;
        try
        {
            var info = new byte[48];
            if (NtQueryInformationProcess(handle, 0, info, info.Length, out _) != 0) return null;
            var peb = (ulong)Marshal.ReadInt64(info, 8);
            if (peb == 0) return null;

            var paramsPtr = ReadPointer(handle, (IntPtr)(long)(peb + 0x20));
            if (paramsPtr == IntPtr.Zero) return null;

            // RTL_USER_PROCESS_PARAMETERS (x64): ImagePathName at 0x60, CommandLine at 0x70, both
            // UNICODE_STRINGs { ushort Length; ushort MaximumLength; wchar_t *Buffer; }.
            var header = new byte[16];
            if (!ReadProcessMemory(handle, (IntPtr)(long)((ulong)paramsPtr + 0x70), header,
                    (IntPtr)header.Length, out var read) || read != header.Length)
                return null;

            var length = (int)BitConverter.ToUInt16(header, 0);
            var bufferPtr = (ulong)Marshal.ReadInt64(header, 8);
            if (length <= 0 || length > 0x10000 || bufferPtr == 0) return null;

            var bytes = new byte[length];
            if (!ReadProcessMemory(handle, (IntPtr)(long)bufferPtr, bytes, (IntPtr)length, out read)
                || read < length)
                return null;
            return Encoding.Unicode.GetString(bytes);
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private static IntPtr ReadPointer(IntPtr process, IntPtr address)
    {
        var buf = new byte[IntPtr.Size];
        if (!ReadProcessMemory(process, address, buf, (IntPtr)buf.Length, out var read)
            || read != buf.Length)
            return IntPtr.Zero;
        return (IntPtr)BitConverter.ToInt64(buf, 0);
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder,
        int ulAf, int tableClass, uint reserved);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, StringBuilder name,
        ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr process, IntPtr baseAddress, byte[] buffer,
        IntPtr size, out IntPtr bytesRead);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr process, int infoClass, byte[] info,
        int infoLength, out int returnLength);
}
