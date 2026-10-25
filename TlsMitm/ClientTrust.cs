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
/// <param name="Image">Executable file name, which is what a process-scope filter names.</param>
public readonly record struct ClientIdentity(ClientTrust Trust, int Pid, string Label, bool Ambiguous, string Image);

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
            return new ClientIdentity(ClientTrust.WindowsStore, 0, "unknown (no TCP owner)", false, "");
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
            return new ClientIdentity(ClientTrust.NodeBundled, pid, $"{exe} (electron node service)", false, exe);

        // Renderers, GPU and the network service all reach TLS through Schannel; the network service
        // is the one that carries page traffic.
        if (cmd.Contains("--type=", StringComparison.OrdinalIgnoreCase))
            return new ClientIdentity(ClientTrust.WindowsStore, pid, $"{exe} (chromium child)", false, exe);

        if (string.Equals(exe, "node.exe", StringComparison.OrdinalIgnoreCase))
            return new ClientIdentity(ClientTrust.NodeBundled, pid, "node.exe", true, exe);

        // A packaged Electron app spawns its own Node children as "app.exe <script>.mjs <args>". That
        // argv has no --type=, so without this it would be logged as the main process even though it
        // is a separate process on the same bundled-store TLS stack.
        if (RunsNodeScript(cmd))
            return new ClientIdentity(ClientTrust.NodeBundled, pid, $"{exe} (electron node worker)", true, exe);

        // An Electron main process has no --type= and verifies with its bundled list; the .asar
        // beside the executable is what distinguishes it from a Chromium browser process, which
        // does not run Node and whose own connections go through its network service child.
        if (LooksLikeElectronApp(imagePath))
            return new ClientIdentity(ClientTrust.NodeBundled, pid, $"{exe} (electron main)", true, exe);

        return new ClientIdentity(ClientTrust.WindowsStore, pid, $"{exe} (no known bundling)", false, exe);
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

    private static unsafe string? QueryCommandLine(int pid)
    {
        // ProcessCommandLineInformation returns a UNICODE_STRING whose Buffer points into the caller's
        // own buffer (measured on 10.0.17763: base + sizeof(UNICODE_STRING)), so it needs only
        // PROCESS_QUERY_LIMITED_INFORMATION - unlike walking the PEB, which needs PROCESS_VM_READ and
        // therefore fails on any process that forbids it. The array is pinned across the call and the
        // read because the kernel writes that pointer, not a string we may chase later.
        const int ProcessCommandLineInformation = 60;
        const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);

        var handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (handle == IntPtr.Zero) return null;
        try
        {
            var size = 0x400;
            for (var attempt = 0; attempt < 2; attempt++)
            {
                var buffer = new byte[size];
                int status;
                int needed;
                fixed (byte* p = buffer)
                {
                    status = NtQueryInformationProcess(handle, ProcessCommandLineInformation, buffer,
                        buffer.Length, out needed);
                    if (status == 0)
                    {
                        var length = *(ushort*)p;
                        var text = *(IntPtr*)(p + 8);
                        var offset = (long)text - (long)p;
                        if (length <= 0 || offset < 16 || offset >= buffer.Length) return null;
                        return Marshal.PtrToStringUni(text, length / 2);
                    }
                }
                if (status != StatusInfoLengthMismatch || needed <= size) return null;
                size = needed;
            }
            return null;
        }
        finally
        {
            CloseHandle(handle);
        }
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

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr process, int infoClass, byte[] info,
        int infoLength, out int returnLength);
}

/// <summary>
/// Narrows interception to a set of client processes. There are two selectors, each usable on either
/// side of the decision: a pid, and an executable name. <c>--pid</c>/<c>--process</c> keep only the
/// named processes, <c>--exclude-pid</c>/<c>--exclude-process</c> drop them, and a flow that is not in
/// scope is left alone - not the packet only, but the whole connection, because a half-redirected
/// flow breaks the client.
/// </summary>
public sealed class ProcessFilter
{
    private readonly HashSet<int> _includePids;
    private readonly HashSet<string> _includeImages;
    private readonly HashSet<int> _excludePids;
    private readonly HashSet<string> _excludeImages;
    private readonly Func<IPAddress, int, ClientIdentity> _identify;

    public ProcessFilter(IEnumerable<int> includePids, IEnumerable<string> includeImages,
        IEnumerable<int> excludePids, IEnumerable<string> excludeImages,
        Func<IPAddress, int, ClientIdentity>? identify = null)
    {
        _includePids = includePids.ToHashSet();
        _includeImages = Names(includeImages);
        _excludePids = excludePids.ToHashSet();
        _excludeImages = Names(excludeImages);
        _identify = identify ?? ((address, port) => ClientProcess.Identify(address, port, out _));
    }

    public bool IsActive =>
        _includePids.Count > 0 || _includeImages.Count > 0 || _excludePids.Count > 0 || _excludeImages.Count > 0;

    public string Describe() =>
        string.Join(", ", new[]
        {
            _includePids.Count > 0 ? $"pid {string.Join('/', _includePids)}" : null,
            _includeImages.Count > 0 ? string.Join('/', _includeImages) : null,
            _excludePids.Count > 0 ? $"not pid {string.Join('/', _excludePids)}" : null,
            _excludeImages.Count > 0 ? $"not {string.Join('/', _excludeImages)}" : null
        }.Where(s => s != null));

    public bool Allows(IPAddress clientAddress, int clientPort, out ClientIdentity identity)
    {
        identity = default;
        if (!IsActive) return true;
        identity = _identify(clientAddress, clientPort);

        // With no include list every flow is a candidate; with one, either key may name it. An unowned
        // flow (pid 0, no image) satisfies neither, and letting it through would mean a request to
        // watch one process silently captures everything the TCP table could not name.
        var included = (_includePids.Count == 0 && _includeImages.Count == 0)
            || _includePids.Contains(identity.Pid)
            || _includeImages.Contains(NormalizeImage(identity.Image));
        if (!included) return false;

        // An exclusion is a hard no even for a flow an include named: the two sides of each pair are
        // the same selector, so "capture chrome but not pid 4000" has to mean the pid wins.
        return !_excludePids.Contains(identity.Pid) && !_excludeImages.Contains(NormalizeImage(identity.Image));
    }

    private static HashSet<string> Names(IEnumerable<string> names) =>
        names.Select(NormalizeImage).Where(name => name.Length > 0).ToHashSet(StringComparer.OrdinalIgnoreCase);

    // The empty string is what an unowned flow carries; it must never turn into ".exe" and match a
    // pattern, so it stays empty and no set can contain it.
    private static string NormalizeImage(string name)
    {
        var file = Path.GetFileName(name.Trim());
        if (file.Length == 0) return "";
        return file.Contains('.') ? file : file + ".exe";
    }
}
