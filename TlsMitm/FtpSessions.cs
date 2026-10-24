using System.Net;
using System.Net.Sockets;
using System.Text;

namespace TlsMitm;

/// <summary>
/// Remembers which FTP server name owns which passive-mode data endpoint. The client learns that
/// endpoint from the control session's 227 reply (RFC 959 §4.2.1) or 229 reply (RFC 2428 §3) and
/// dials it seconds later, often without any SNI, so the reply is the only thing that ties the
/// address back to a hostname.
/// </summary>
internal sealed class FtpSessionRegistry
{
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);

    private readonly object _gate = new();
    private readonly Dictionary<Key, Entry> _entries = new();

    public FtpControlSniffer SnifferFor(IPAddress clientIp, IPAddress controlServerIp, string host) =>
        new(this, clientIp, controlServerIp, host);

    public void Register(IPAddress clientIp, IPAddress dataIp, int dataPort, string host)
    {
        if (dataPort is < 1 or > 65535) return;

        var key = new Key(Normalize(clientIp), Normalize(dataIp), (ushort)dataPort);
        lock (_gate)
        {
            Sweep();
            _entries[key] = new Entry(host, DateTime.UtcNow);
        }
        Console.WriteLine($"[FTPS] data endpoint {dataIp}:{dataPort} belongs to {host}");
    }

    public string? Lookup(IPAddress clientIp, IPAddress dataIp, int dataPort)
    {
        if (dataPort is < 1 or > 65535) return null;

        var key = new Key(Normalize(clientIp), Normalize(dataIp), (ushort)dataPort);
        lock (_gate)
        {
            if (!_entries.TryGetValue(key, out var entry)) return null;
            if (DateTime.UtcNow - entry.RegisteredAt > Ttl)
            {
                _entries.Remove(key);
                return null;
            }
            return entry.Host;
        }
    }

    private void Sweep()
    {
        List<Key>? expired = null;
        var now = DateTime.UtcNow;
        foreach (var (key, entry) in _entries)
        {
            if (now - entry.RegisteredAt <= Ttl) continue;
            (expired ??= new List<Key>()).Add(key);
        }
        if (expired == null) return;
        foreach (var key in expired) _entries.Remove(key);
    }

    internal static string Normalize(IPAddress address) =>
        (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString();

    private readonly record struct Key(string ClientIp, string DataIp, ushort Port);

    private readonly record struct Entry(string Host, DateTime RegisteredAt);
}

/// <summary>
/// One listener standing in for the FTP client's own data socket during an active-mode transfer.
/// The port is what the control session now advertises, the client is the address the peer really
/// listens on.
/// </summary>
internal sealed class FtpActiveChannel
{
    public required TcpListener Listener { get; init; }
    public required string Host { get; init; }
    public required int Port { get; init; }
    // The data channel is verified by the same client as the control session, so its leaf has to come
    // from the same CA family even though the connect() came from the server.
    public required ClientTrust Trust { get; init; }

    public IPEndPoint? RealClient { get; set; }
}

/// <summary>
/// Reads the plaintext of one FTPS control session as it relays by, in both directions.
/// Server to client it records the passive-mode endpoints. Client to server it turns an active-mode
/// PORT/EPRT into a port this process listens on, which is the only way to see that data channel:
/// the server opens it, so no outbound packet carries the client's destination and the
/// outbound-only filter has nothing to redirect.
/// </summary>
internal sealed class FtpControlSniffer
{
    private const int MarkerLen = 4;
    private const int LineCap = 256;

    // "PORT ", "EPRT ", "PROT ", "PBSZ " - five bytes is enough to classify an FTP command line.
    private const int VerbLen = 5;

    private readonly FtpSessionRegistry _registry;
    private readonly IPAddress _clientIp;
    private readonly IPAddress _controlServerIp;
    private readonly string _host;

    private readonly byte[] _head = new byte[MarkerLen];
    private readonly StringBuilder _line = new();

    private int _headLen;
    private bool _headRejected;
    private bool _collecting;
    private bool _greetingChecked;

    // Client to server: a command line withheld across chunks, plus the protocol state it reveals.
    private readonly byte[] _held = new byte[VerbLen + LineCap];
    private int _heldLen;
    private byte[]? _out;
    private int _outLen;
    private bool _rebuilt;

    private bool _ftpConfirmed;
    private bool _protPrivate;

    /// <summary>
    /// Asks for a port to advertise in place of the client's, given the endpoint the client really
    /// named. Returning null leaves the command exactly as the client wrote it.
    /// </summary>
    public Func<IPEndPoint, int?>? ActivePortRequest { get; set; }

    internal FtpControlSniffer(FtpSessionRegistry registry, IPAddress clientIp, IPAddress controlServerIp, string host)
    {
        _registry = registry;
        _clientIp = clientIp;
        _controlServerIp = controlServerIp;
        _host = host;
    }

    public void TapServer(ReadOnlySpan<byte> data)
    {
        // An FTP server greets with 220 ("Service ready for new user", RFC 959 §4.2.1) before the
        // client says anything; nothing else does, so this is what separates an FTP control session
        // from a peer whose bytes happen to look like a verb.
        if (!_greetingChecked && data.Length >= MarkerLen)
        {
            _greetingChecked = true;
            if (data[0] == (byte)'2' && data[1] == (byte)'2' && data[2] == (byte)'0' && data[3] == (byte)' ')
            {
                _ftpConfirmed = true;
                Console.WriteLine($"[FTPS] {_host} greeted as an FTP server");
            }
        }

        var pos = 0;
        while (pos < data.Length)
        {
            if (_collecting)
            {
                var nl = data.Slice(pos).IndexOf((byte)'\n');
                var take = nl < 0 ? data.Length - pos : nl;
                var abandoned = _line.Length + take > LineCap;
                if (!abandoned) _line.Append(Encoding.ASCII.GetString(data.Slice(pos, take)));

                pos += take;
                if (nl < 0)
                {
                    if (abandoned)
                    {
                        Reset();
                        _headRejected = true;
                    }
                    return;
                }
                pos++;

                if (abandoned)
                {
                    Reset();
                    continue;
                }

                var line = _line.ToString();
                Reset();
                TryRecord(line);
                continue;
            }

            if (_headRejected)
            {
                var nl = data.Slice(pos).IndexOf((byte)'\n');
                if (nl < 0) return;
                pos += nl + 1;
                // Re-arm the head window for the next line, otherwise the stale bytes keep deciding
                // which lines are interesting and only the very first line is ever read.
                _headLen = 0;
                _headRejected = false;
                continue;
            }

            var chunk = Math.Min(MarkerLen - _headLen, data.Length - pos);
            data.Slice(pos, chunk).CopyTo(_head.AsSpan(_headLen));
            _headLen += chunk;
            pos += chunk;
            if (_headLen < MarkerLen) return;

            if (IsReplyHead(_head))
            {
                _collecting = true;
                _line.Clear();
                _line.Append(Encoding.ASCII.GetString(_head));
            }
            else
            {
                _headRejected = true;
            }
        }
    }

    /// <summary>
    /// Returns null to forward the chunk untouched, or the bytes to forward in its place. Withholding
    /// a line makes the whole chunk rebuilt, so the bytes ahead of it are copied as well.
    /// </summary>
    public byte[]? RewriteClient(ReadOnlySpan<byte> data)
    {
        _outLen = 0;
        _rebuilt = false;
        var copied = 0;
        var pos = 0;

        if (_heldLen > 0 && _heldLen < VerbLen)
        {
            // Carried bytes are already out of the stream, so this chunk can no longer be forwarded
            // as it stands.
            Rebuild(data.Length);
            var take = Math.Min(VerbLen - _heldLen, data.Length);
            data.Slice(0, take).CopyTo(_held.AsSpan(_heldLen));
            _heldLen += take;
            pos = take;

            if (_heldLen < VerbLen) return Finish(data, ref copied);

            if (!IsVerbHead(_held))
            {
                Emit(_held.AsSpan(0, VerbLen));
                _heldLen = 0;
                var nl = data.Slice(pos).IndexOf((byte)'\n');
                if (nl < 0)
                {
                    Emit(data.Slice(pos));
                    return Finish(data, ref copied);
                }
                Emit(data.Slice(pos, nl + 1));
                pos += nl + 1;
                copied = pos;
            }
        }

        while (pos < data.Length)
        {
            if (_heldLen > 0)
            {
                var nl = data.Slice(pos).IndexOf((byte)'\n');
                var got = AppendHeld(data.Slice(pos, nl < 0 ? data.Length - pos : nl + 1));
                pos += got;

                if (_heldLen == 0)
                {
                    // The line outgrew the buffer, so it cannot be a command: it went out as it came
                    // and the scan resumes mid-line.
                    Rebuild(data.Length);
                    copied = pos;
                    continue;
                }

                if (nl < 0) return Finish(data, ref copied);

                Rebuild(data.Length);
                FlushHeldLine();
                copied = pos;
                continue;
            }

            var remaining = data.Length - pos;
            if (remaining >= VerbLen)
            {
                if (IsVerbHead(data.Slice(pos, VerbLen)))
                {
                    Rebuild(data.Length);
                    FlushRegion(data, ref copied, pos);
                    data.Slice(pos, VerbLen).CopyTo(_held);
                    _heldLen = VerbLen;
                    pos += VerbLen;
                    continue;
                }

                var nl = data.Slice(pos, remaining).IndexOf((byte)'\n');
                var next = nl < 0 ? data.Length : pos + nl + 1;
                FlushRegion(data, ref copied, next);
                pos = next;
                continue;
            }

            // The chunk ends inside a line's first bytes, so the verb cannot be read off it yet.
            Rebuild(data.Length);
            FlushRegion(data, ref copied, pos);
            data.Slice(pos, remaining).CopyTo(_held);
            _heldLen = remaining;
            return Finish(data, ref copied);
        }

        return Finish(data, ref copied);
    }

    private void Rebuild(int sizeHint)
    {
        _rebuilt = true;
        EnsureOut(sizeHint + _held.Length);
    }

    private void EnsureOut(int sizeHint) => _out ??= new byte[Math.Max(64, sizeHint)];

    /// <summary>Copy the bytes the scan walked over without withholding them.</summary>
    private void FlushRegion(ReadOnlySpan<byte> data, ref int copied, int upto)
    {
        if (!_rebuilt || upto <= copied) return;
        Emit(data.Slice(copied, upto - copied));
        copied = upto;
    }

    private void Emit(ReadOnlySpan<byte> bytes)
    {
        if (_outLen + bytes.Length > _out!.Length)
        {
            var grown = new byte[Math.Max(_outLen + bytes.Length, _out.Length * 2)];
            Array.Copy(_out, grown, _outLen);
            _out = grown;
        }
        bytes.CopyTo(_out.AsSpan(_outLen));
        _outLen += bytes.Length;
    }

    /// <summary>Withhold more of the current command line; returns how many bytes were taken.</summary>
    private int AppendHeld(ReadOnlySpan<byte> bytes)
    {
        var take = Math.Min(bytes.Length, _held.Length - _heldLen);
        bytes.Slice(0, take).CopyTo(_held.AsSpan(_heldLen));
        _heldLen += take;
        if (_heldLen < _held.Length) return take;

        // A command line never runs this long: give up on it and forward what was held.
        if (take < bytes.Length && bytes[take] != (byte)'\n')
        {
            Rebuild(bytes.Length);
            Emit(_held.AsSpan(0, _heldLen));
            _heldLen = 0;
        }
        return take;
    }

    private byte[]? Finish(ReadOnlySpan<byte> data, ref int copied)
    {
        if (!_rebuilt) return null;
        if (_heldLen == 0) FlushRegion(data, ref copied, data.Length);
        return _outLen == 0 ? Array.Empty<byte>() : _out.AsSpan(0, _outLen).ToArray();
    }

    private void FlushHeldLine()
    {
        var len = _heldLen;
        _heldLen = 0;
        Emit(Classify(_held.AsSpan(0, len)) ?? _held.AsSpan(0, len));
    }

    private byte[]? Classify(ReadOnlySpan<byte> line)
    {
        var termLen = 0;
        if (line[^1] == (byte)'\n')
        {
            termLen = 1;
            if (line.Length > 1 && line[^2] == (byte)'\r') termLen = 2;
        }
        var term = termLen == 2 ? "\r\n" : termLen == 1 ? "\n" : "";
        var body = Encoding.ASCII.GetString(line.Slice(0, line.Length - termLen));
        var verb = Encoding.ASCII.GetString(line.Slice(0, 4)).ToUpperInvariant();
        var args = body.Length > VerbLen ? body.Substring(VerbLen) : string.Empty;

        switch (verb)
        {
            // PBSZ 0 and PROT P/C are RFC 4217 §9; either one proves this is the FTP control channel.
            case "PBSZ":
                _ftpConfirmed = true;
                return null;
            case "PROT":
                var mode = args.Trim().ToUpperInvariant();
                if (mode is "P" or "C") _ftpConfirmed = true;
                _protPrivate = mode == "P";
                Console.WriteLine($"[FTPS] {_host} data protection is {(_protPrivate ? "private" : "clear")}");
                return null;
            case "PORT":
                return RewritePort(args, term);
            case "EPRT":
                return RewriteEprt(args, term);
            default:
                return null;
        }
    }

    // "PORT 192,168,1,50,3,232" - four address octets then the port split in two bytes.
    private byte[]? RewritePort(string args, string term)
    {
        var octets = args.Split(',');
        if (octets.Length != 6) return null;

        var raw = new byte[6];
        for (var i = 0; i < raw.Length; i++)
            if (!byte.TryParse(octets[i].Trim(), out raw[i])) return null;

        return Substitute(new IPAddress(raw[..4]), (raw[4] << 8) | raw[5], term, eprt: false,
            prefix: $"PORT {raw[0]},{raw[1]},{raw[2]},{raw[3]},");
    }

    // "EPRT |1|192.168.1.50|50000|" - netid 1 names an IPv4 address, netid 2 an IPv6 one. RFC 2428
    // §2 defines both; the listener that stands in for the client is dual-stack, so either can be held.
    private byte[]? RewriteEprt(string args, string term)
    {
        var parts = args.Split('|');
        if (parts.Length < 4 || (parts[1] != "1" && parts[1] != "2")) return null;
        if (!IPAddress.TryParse(parts[2], out var advertised)) return null;
        if (!int.TryParse(parts[3].Trim(), out var realPort)) return null;

        // The netid has to agree with the literal, or the server would be told to dial an address of
        // the other family than the one it was given.
        var netid = parts[1];
        var expected = netid == "2" ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
        if (advertised.AddressFamily != expected) return null;

        return Substitute(advertised, realPort, term, eprt: true, prefix: $"EPRT |{netid}|{advertised}|");
    }

    private byte[]? Substitute(IPAddress advertised, int realPort, string term, bool eprt, string prefix)
    {
        // The data channel is only worth taking over once the client has asked for protected data
        // with PROT P (RFC 4217 §9); substituting a port in the clear would break a transfer that
        // already works.
        if (!_ftpConfirmed || !_protPrivate || ActivePortRequest is not { } request) return null;

        // A client behind NAT names an address the server reaches through it, not one this machine
        // owns, and only the client's own address can carry a port we are listening on.
        if (FtpSessionRegistry.Normalize(advertised) != FtpSessionRegistry.Normalize(_clientIp))
        {
            Console.WriteLine($"[FTPS] {_host} named {advertised}, not this client's address: leaving active mode alone");
            return null;
        }

        var substitute = request(new IPEndPoint(advertised, realPort));
        if (substitute == null || substitute == realPort) return null;

        var port = substitute.Value;
        Console.WriteLine($"[FTPS] {_host} active mode: advertising port {port} instead of {realPort}");
        return Encoding.ASCII.GetBytes(eprt
            ? $"{prefix}{port}|{term}"
            : $"{prefix}{port >> 8},{port & 0xFF}{term}");
    }

    private static bool IsVerbHead(ReadOnlySpan<byte> head) =>
        head[VerbLen - 1] == (byte)' '
        && (Matches(head.Slice(0, 4), "PORT") || Matches(head.Slice(0, 4), "EPRT")
            || Matches(head.Slice(0, 4), "PROT") || Matches(head.Slice(0, 4), "PBSZ"));

    // Setting bit 0x20 folds both an ASCII letter and the literals below onto their lower case, so
    // the comparison holds for PORT and port alike.
    private static bool Matches(ReadOnlySpan<byte> four, string verb)
    {
        for (var i = 0; i < verb.Length; i++)
            if ((four[i] | 0x20) != (verb[i] | 0x20)) return false;
        return true;
    }

    private void Reset()
    {
        _headLen = 0;
        _headRejected = false;
        _collecting = false;
        _line.Clear();
    }

    private static bool IsReplyHead(byte[] head) =>
        head[0] == (byte)'2' && head[1] == (byte)'2'
        && (head[2] == (byte)'7' || head[2] == (byte)'9') && head[3] == (byte)' ';

    private void TryRecord(string line)
    {
        var open = line.IndexOf('(');
        if (open < 0) return;
        var close = line.IndexOf(')', open + 1);
        var body = close > open ? line.Substring(open + 1, close - open - 1) : line.Substring(open + 1);

        if (line[2] == '7') RecordPasv(body);
        else RecordEpsv(body);
    }

    // "227 Entering Passive Mode (198,51,100,7,44,9)" - the address is carried in the reply itself
    // (RFC 959 §4.2.1: h1,h2,h3,h4,p1,p2).
    private void RecordPasv(string body)
    {
        var octets = body.Split(',');
        if (octets.Length != 6) return;

        var raw = new byte[6];
        for (var i = 0; i < raw.Length; i++)
        {
            if (!byte.TryParse(octets[i].Trim(), out raw[i])) return;
        }

        var port = (raw[4] << 8) | raw[5];
        var advertised = new IPAddress(raw[..4]);
        _registry.Register(_clientIp, advertised, port, _host);

        // A server behind NAT advertises its private address and the client dials the address it
        // actually reached, which is the control connection's.
        if (!advertised.Equals(_controlServerIp))
            _registry.Register(_clientIp, _controlServerIp, port, _host);
    }

    // "229 Entering Extended Passive Mode (|||50212|)" - EPSV carries no address because, as RFC 2428
    // §3 puts it, the data connection "will be the same network protocol used by the control
    // connection", and the same address the control session already knows.
    private void RecordEpsv(string body)
    {
        var parts = body.Split('|');
        if (parts.Length < 4 || !int.TryParse(parts[3].Trim(), out var port)) return;
        _registry.Register(_clientIp, _controlServerIp, port, _host);
    }
}
