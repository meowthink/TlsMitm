using System.Buffers.Binary;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using HelloFingerprint;
using static HelloFingerprint.HelloBuilder;

// Decodes a TLS hello into a fingerprint: a ClientHello into JA3 and JA4, a ServerHello into JA3S and
// JA4S. Four inputs, one decoder:
//   check                    the published vectors for all four, so a wrong hash fails here not in a report
//   self [alpn]              the hello this machine's SslStream produces with the proxy's upstream options
//   listen <port> [n]        whatever a real client next to it sends
//   pcap <file> [n]          classic pcap, TCP payloads reassembled per direction and read in both of them
if (args.Length == 0) { Console.WriteLine(usage()); return 1; }
switch (args[0])
{
    case "check": return Check();
    case "self": return await SelfAsync(args.Length > 1 ? args[1] : null);
    case "listen": return await ListenAsync(int.Parse(args[1]), args.Length > 2 ? int.Parse(args[2]) : 1);
    case "pcap": return Pcap(args[1], args.Length > 2 ? int.Parse(args[2]) : 8);
    default: Console.WriteLine(usage()); return 1;
}

static string usage() =>
    "usage: hellofingerprint check | self [h2,http/1.1] | listen <port> [n] | pcap <file> [n]";

// ---- check ----

static int Check()
{
    var failures = 0;

    // JA3's own field order and MD5, against the two examples published with the algorithm.
    foreach (var (text, expected) in new[]
    {
        ("769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0", "ada70206e40642a3e4461f35503241d5"),
        ("769,4-5-10-9-100-98-3-6-19-18-99,,,", "de350869b8c85de67a350c8d186f11e6"),
    })
    {
        var got = Convert.ToHexString(MD5.HashData(Encoding.ASCII.GetBytes(text))).ToLowerInvariant();
        Report("JA3", text.Length > 40 ? text[..40] + "..." : text, got, expected, ref failures);
    }

    // JA4's section b and c inputs, exactly as the specification works them: cipher list sorted,
    // extension list sorted with SNI and ALPN removed, then the signature algorithms appended in order.
    var ciphers = "002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9";
    var extensions = "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01";
    var sigalgs = "0403,0804,0401,0503,0805,0501,0806,0601";
    foreach (var (text, expected) in new[]
    {
        (ciphers, "8daaf6152771"),
        (extensions + "_" + sigalgs, "e5627efa2ab1"),
        (extensions, "6d807ffa2a79"),
    })
    {
        var got = Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(text)))[..12].ToLowerInvariant();
        Report("JA4", text[..Math.Min(34, text.Length)] + "...", got, expected, ref failures);
    }

    // The parser itself, on a hello assembled here. Its legacy version is 0x0303 while supported_versions
    // reaches 0x0304, which is the one fixture that pins both readings at once: JA3 must report 771 and
    // JA4 must report 13. A GREASE cipher, extension and group must drop out of every field.
    var built = BuildHello(version: 0x0303,
        ciphers: [0x1a1a, 0x1301, 0x1303, 0x002f],
        // 0x11ec is X25519MLKEM768 and 0x0017 secp256r1; JA3 prints these code points in decimal.
        extensions:
        [
            (0x0000, Sni("probe.example")), (0x000a, Groups([0x11ec, 0x1a1a, 0x0017])),
            (0x000b, PointFormats([0])), (0x000d, SigAlgs([0x0403, 0x0804])),
            (0x002b, SupportedVersions([0x0304, 0x3a3a])), (0xdada, []), (0x0010, Alpn(["h2"])),
        ]);
    var hello = ClientHello.Parse(built) ?? throw new Exception("the assembled hello did not parse");
    void Expect(string label, string got, string want)
    {
        var ok = got == want;
        Console.WriteLine($"{(ok ? "ok   " : "FAIL ")}hello.{label} = {got}" + (ok ? "" : $" (expected {want})"));
        if (!ok) failures++;
    }
    Expect("ciphers", string.Join(',', hello.Ciphers), "4865,4867,47");
    Expect("extensions", string.Join(',', hello.Extensions), "0,10,11,13,43,16");
    Expect("groups", string.Join(',', hello.Groups), "4588,23");
    Expect("point formats", string.Join(',', hello.PointFormats), "0");
    Expect("sni", hello.ServerName ?? "(none)", "probe.example");
    Expect("alpn", string.Join(',', hello.Alpn.Select(Encoding.ASCII.GetString)), "h2");
    Console.WriteLine($"       ja3 string   : {hello.Ja3String()}");
    Expect("ja3", hello.Ja3(), "a2791aa645c413a276f4e24d452c5cd2");
    Expect("ja4", hello.Ja4(), "t13d0306h2_e1e30aeaa564_fb71836bce29");

    // JA3S and JA4S, on the hello the server sends back. Each record below was cut byte for byte out of a
    // capture FoxIO publishes with its reference implementation: the expected JA3S is Wireshark 4.0.2's
    // tls.handshake.ja3s_full for the same record, and the expected JA4S is the JA4S that repo prints as
    // its own reference output. The two sources are independent of each other and of this file.
    foreach (var (shape, hex, ja3s, ja4s) in new[]
    {
        ("tls 1.2, alpn h2",
            "16030300640200006003035f0236c07f47bfb12dc2da706ecb3fe7f9eeac9968cc2ddf444f574e4752440120b89ff1ab695278c69b8a73f76242ef755e0b13dc6d459aaaa784fec9c2dfce34cca900001800000000ff01000100000b00020100001000050003026832",
            "7f76f3e952a1bc7d407366fafe1db7ed", "t1204h2_cca9_1428ce7b4018"),
        ("tls 1.3, three extensions",
            "16030300800200007c0303c745649ae52288ebf76ff4753d2ce034bd1489385ced14f7753bc2aba50a509320f87358566bf7d8aa9c26f426818527fe29c66957c2acb0796d475fedac1814ba1301000034002b0002030400330024001d00209ec1e06fb26e8147e8bc50dc8873dbc9d610563e6467bcd24ce2da5c0c071e54002900020000",
            "fcb2d4d0991292272fcb1e464eedfd43", "t130300_1301_0ee26285a86f"),
        ("tls 1.2, alpn http/1.1",
            "160303005402000050030397bd649543af69065795e81252e579fd1e1af37bc600b3bd674ecb1e402fffe600c02b000028ff0100010000000000000b00040300010200230000000500000010000b000908687474702f312e31",
            "489634f4293b3c4e2bb342e3117dc2c3", "t1206h1_c02b_9bd66850b8f2"),
    })
    {
        var selection = ServerHello.Parse(Convert.FromHexString(hex))
            ?? throw new Exception($"{shape}: the reference ServerHello did not parse");
        Expect("ja3s " + shape, selection.Ja3S(), ja3s);
        Expect("ja4s " + shape, selection.Ja4S(), ja4s);
    }

    // The two shapes this proxy's own terminator answers with, read out of a floor run. Wireshark 4.0.2
    // prints the same JA3S strings for them ("771,47," and "771,4865,43-51") once the records are put in a
    // capture, and coreutils' md5sum/sha256sum reproduce both hashes over those strings. The 1.2 record is
    // the one RFC 5246 §7.4.1.3 allows to carry no extension field at all; its empty third field and the
    // JA4S all-zero extension hash are what a hello with nothing in it has to produce.
    foreach (var (shape, hex, ja3s, ja4s) in new[]
    {
        ("tls 1.2, no extension field",
            "160303004a020000460303a3aecde928c2de76423c3bf93abfb761346329f34610db21444f574e47524401205d5f54a9ecd1f81e04ea36c026a6a4b79094a55ebc4b773d0cca8ba581a2bd05002f00",
            "5397c414a9ebeaff1bf18b70ca22eaa0", "t120000_002f_000000000000"),
        ("tls 1.3, two extensions",
            "160303005a02000056030342d18409e2e6073343f9f5b85501902df02e91cd2b402135e672c6df0489e7d200130100002e002b0002030400330024001d0020b6a33a8a0e90f8b0e9ce2b61a99d946e2eeac230d2a0200101d564bbf1dec752",
            "f4febc55ea12b31ae17cfb7e614afda8", "t130200_1301_a56c5b993250"),
    })
    {
        var selection = ServerHello.Parse(Convert.FromHexString(hex))
            ?? throw new Exception($"{shape}: the terminator's own ServerHello did not parse");
        Expect("ja3s " + shape, selection.Ja3S(), ja3s);
        Expect("ja4s " + shape, selection.Ja4S(), ja4s);
    }

    // A HelloRetryRequest is a server_hello (2) in every other respect (RFC 8446 §4.1.3), and §4.1.4
    // limits its extensions to what the client needs in order to retry, so reading one as a selection
    // would fingerprint something the RFC says is not a selection.
    var retry = Convert.FromHexString(
        "1603030058020000540303cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c20f2ae74a36b070777bc9d86ea69b37a1bea722aa41de7069fff1dd8ecc78c7d2a130200000c002b00020304003300020017");
    Expect("retry recognised", ServerHello.IsHelloRetryRequest(retry) ? "yes" : "no", "yes");
    Expect("retry refused", ServerHello.Parse(retry) is null ? "no fingerprint" : "hashed", "no fingerprint");

    Console.WriteLine(failures == 0 ? "check: all vectors match" : $"check: {failures} mismatched");
    return failures == 0 ? 0 : 1;
}

static void Report(string algorithm, string input, string got, string expected, ref int failures)
{
    var ok = got == expected;
    Console.WriteLine($"{(ok ? "ok   " : "FAIL ")}{algorithm} {input} => {got}" + (ok ? "" : $" (expected {expected})"));
    if (!ok) failures++;
}

// ---- self ----

static async Task<int> SelfAsync(string? alpnArg)
{
    var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    var acceptTask = listener.AcceptTcpClientAsync();

    // The options the proxy's upstream leg uses, so this is the hello a server sees from us.
    var options = new SslClientAuthenticationOptions
    {
        TargetHost = "probe.example",
        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
    };
    if (alpnArg is not null)
        options.ApplicationProtocols = alpnArg.Split(',')
            .Select(p => new SslApplicationProtocol(p)).ToList();

    using var client = new TcpClient();
    await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
    // Same construction as the proxy's upstream leg (MitmProxy's SslStream over the raw socket plus
    // these options), so what the peer below reads is the hello a server sees from us.
    using var tls = new SslStream(client.GetStream(), false);
    // There is no server behind this listener, so the handshake is expected to end in an error once the
    // socket closes; only the hello it wrote matters.
    var handshake = tls.AuthenticateAsClientAsync(options);

    using var peer = await acceptTask;
    var record = await ReadRecordAsync(peer.GetStream(), TimeSpan.FromSeconds(10));
    client.Close();
    listener.Stop();
    try { await handshake; }
    catch (Exception ex) { Console.WriteLine($"(handshake ended as it must with no server: {ex.GetType().Name})"); }

    return Print(record, $"SslStream on this machine (alpn: {alpnArg ?? "none"})");
}

// ---- listen ----

static async Task<int> ListenAsync(int port, int count)
{
    var listener = new TcpListener(IPAddress.Any, port);
    listener.Start();
    Console.WriteLine($"listening on {port} for {count} ClientHello(s)");
    for (var i = 0; i < count; i++)
    {
        using var peer = await listener.AcceptTcpClientAsync();
        var record = await ReadRecordAsync(peer.GetStream(), TimeSpan.FromSeconds(15));
        Console.WriteLine($"--- hello {i + 1} from {peer.Client.RemoteEndPoint} ---");
        Print(record, "captured from a live client");
    }
    listener.Stop();
    return 0;
}

// ---- pcap ----

static int Pcap(string path, int max)
{
    var bytes = File.ReadAllBytes(path);
    var streams = new Dictionary<string, MemoryStream>();
    var printed = 0;
    try
    {
        foreach (var frame in Frames(bytes))
        {
            var payload = TcpStream(frame.Span, out var key);
            if (payload.Length == 0) continue;
            var buffer = streams.TryGetValue(key, out var existing) ? existing : streams[key] = new MemoryStream();
            buffer.Write(payload);
            var record = TakeRecord(buffer);
            if (record is null) continue;
            // Handshake type 1 is the client's hello and type 2 the server's. What follows them in the same
            // direction — a Certificate, a ServerKeyExchange — carries nothing either fingerprint reads.
            if (record.Value.Length < 6 || record.Value.Span[5] is not (0x01 or 0x02)) continue;
            Console.WriteLine($"--- {key}, {record.Value.Length} byte record ---");
            printed += Print(record.Value, $"from {Path.GetFileName(path)}");
            if (printed >= max) break;
        }
    }
    catch (InvalidDataException ex)
    {
        Console.WriteLine(ex.Message);
        return 1;
    }
    if (printed == 0) Console.WriteLine("(no complete hello in the TCP payloads of this capture)");
    return printed == 0 ? 2 : 0;

    static IEnumerable<ReadOnlyMemory<byte>> Frames(byte[] file)
    {
        static uint Be32(byte[] b, int at) => BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(at));
        static uint Le32(byte[] b, int at) => BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(at));

        var big = false;
        switch (Le32(file, 0))
        {
            case 0xa1b2c3d4u or 0xa1b23c4du: break;             // microsecond and nanosecond resolution
            case 0xd4c3b2a1u or 0x4d3cb2a1u: big = true; break;  // the same, written byte-swapped
            case 0x1a0d0d0au or 0x0a0d0d1au:
                throw new InvalidDataException("this is pcapng; re-save it as classic pcap (-P) for this tool");
            default:
                throw new InvalidDataException($"not a classic pcap (magic 0x{Le32(file, 0):x8})");
        }
        uint Length(byte[] b, int at) => big ? Be32(b, at) : Le32(b, at);
        if (file.Length < 24) throw new InvalidDataException("truncated pcap: no global header");

        // Octet 20 of the global header is the link-layer type (DLT_*, tcp(7) §2), and the frames this
        // tool walks assume Ethernet. A loopback capture (DLT_NULL, 0) holds valid hellos in a framing
        // TcpStream does not read, so name that instead of reporting a capture with nothing in it.
        var network = Length(file, 20);
        if (network != 1)
            throw new InvalidDataException($"link type {network}, this tool reads Ethernet frames (type 1)");

        // 24-octet global header, then 16-octet record headers: ts_sec, ts_usec, incl_len, orig_len.
        var off = 24;
        while (off + 16 <= file.Length)
        {
            var included = (int)Length(file, off + 8);
            if (included <= 0 || off + 16 + included > file.Length) yield break;
            yield return file.AsMemory(off + 16, included);
            off += 16 + included;
        }
    }

    // A hello spans MTUs once a post-quantum key_share is in it, so the payloads of one direction are
    // reassembled before a record is cut out of them.
    static ReadOnlyMemory<byte>? TakeRecord(MemoryStream buffer)
    {
        var span = buffer.GetBuffer().AsSpan(0, (int)buffer.Length);
        if (span.Length < 5) return null;
        if (span[0] != 0x16)
        {
            // A record that is not a handshake message means the keys have changed and everything after it
            // in this direction is encrypted, so this stream has nothing left to read.
            buffer.SetLength(0);
            return null;
        }
        var length = (span[3] << 8) | span[4];
        if (span.Length < 5 + length) return null;
        var record = span[..(5 + length)].ToArray();
        var rest = span[(5 + length)..].ToArray();
        buffer.SetLength(0);
        // A server that coalesced a retry and its follow-on record into one segment gets both read.
        if (rest.Length > 0) buffer.Write(rest);
        return record;
    }
}

static ReadOnlySpan<byte> TcpStream(ReadOnlySpan<byte> frame, out string key)
{
    key = "";
    if (frame.Length < 14) return [];
    var ethType = (frame[12] << 8) | frame[13];
    var ipv4 = ethType == 0x0800;
    if (!ipv4 && ethType != 0x86dd) return [];
    var l3 = frame[14..];
    var header = ipv4 ? (l3[0] & 0xf) * 4 : 40;   // IPv6 has a fixed header (RFC 8200 §3)
    if (l3.Length < header + 20 || (ipv4 ? l3[9] : l3[6]) != 6) return [];
    var options = (l3[header + 12] >> 4) * 4;
    var srcPort = (l3[header] << 8) | l3[header + 1];
    var dstPort = (l3[header + 2] << 8) | l3[header + 3];

    // IPv4's total length covers the header too (RFC 791 §3.1) and IPv6's payload length does not
    // (RFC 8200 §3); both say where the segment ends inside a frame that may be zero-padded past it to
    // the 64-octet Ethernet minimum, so the padding is cut here rather than handed to the reassembly.
    var end = ipv4 ? (l3[2] << 8) | l3[3] : header + ((l3[4] << 8) | l3[5]);
    var data = header + options;
    if (options < 20 || data > end || l3.Length < end) return [];
    key = $"{new IPAddress(l3.Slice(ipv4 ? 12 : 8, ipv4 ? 4 : 16))}:{srcPort}->{dstPort}";
    return l3[data..end];
}

static async Task<ReadOnlyMemory<byte>> ReadRecordAsync(NetworkStream stream, TimeSpan timeout)
{
    var header = new byte[5];
    using var cts = new CancellationTokenSource(timeout);
    await stream.ReadExactlyAsync(header, cts.Token);
    var length = (header[3] << 8) | header[4];
    var record = new byte[5 + Math.Min(length, 16384)];
    header.CopyTo(record, 0);
    await stream.ReadExactlyAsync(record.AsMemory(5, record.Length - 5), cts.Token);
    return record;
}

static int Print(ReadOnlyMemory<byte> record, string source)
{
    if (ClientHello.Parse(record.Span) is ClientHello hello)
    {
        Console.WriteLine($"== {source} ==");
        Console.WriteLine(hello.ToString());
        return 1;
    }
    // The same handshake read from the other side, which is what a client of ours sees.
    if (ServerHello.IsHelloRetryRequest(record.Span))
    {
        Console.WriteLine($"== {source} == HelloRetryRequest: nothing selected yet (RFC 8446 §4.1.3)");
        return 1;
    }
    if (ServerHello.Parse(record.Span) is ServerHello selection)
    {
        Console.WriteLine($"== {source} ==");
        Console.WriteLine(selection.ToString());
        return 1;
    }
    Console.WriteLine($"{source}: not a parseable hello ({record.Length} bytes)");
    return 0;
}
