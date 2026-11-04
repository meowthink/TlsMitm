// Three questions:
//  1. synthetic chain: when a leaf is signed by an ECDSA intermediate that is in NO local store,
//     does SslStream put the intermediate + root on the wire? Compares ServerCertificate against
//     ServerCertificateContext.
//  2. "emsign <certsDir>": the same question for the real emSign intermediates, recovered scalars
//     and cross-signed root driving the real CertEngine/EmSignCa from TlsMitm. Serves one
//     connection so a strict Node client using its DEFAULT store can render the verdict.
//  3. "floor": the version floor the libssl terminator actually runs with, read off the wire — hellos
//     offering only TLS 1.0, 1.1, 1.2 or 1.3, plus a real client that has to terminate and be served.
using System.Net;
using System.Formats.Asn1;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using HelloFingerprint;
using TlsMitm;

var mode = args.Length > 0 ? args[0] : "gen";

if (mode == "emsign")
{
    await RunEmSignAsync(args[1]);
    return;
}

// Serves the real CertEngine-shaped Fiddler leaf so a strict curl can render a verdict on it
// without admin: curl --connect-to host:443:127.0.0.1:<port> https://host/
if (mode == "fiddler")
{
    await ServeFiddlerLeafAsync(args[1], int.Parse(args[2]), args.Length > 3 ? args[3] : "plain");
    return;
}

// Serves the real emSign leaf over the libssl leg (the one MitmProxy uses for an emSign chain), with
// a chosen amount of the chain on the wire, so a strict Node/Electron client names the verify error
// for each shape: emserve <certsDir> <port> [full|no-anchor|no-intermediate|leaf] [caIndex]
if (mode == "emserve")
{
    await ServeEmSignShapeAsync(args[1], int.Parse(args[2]),
        args.Length > 3 ? args[3] : "full", args.Length > 4 ? int.Parse(args[4]) : 0);
    return;
}

// Version floor of the libssl terminator: hand-assembled hellos that differ only in the version they
// offer, plus one real SChannel client that has to finish the handshake and read the response. Exit
// code 0 means 1.2 and 1.3 terminate and 1.0 and 1.1 are refused.
if (mode == "floor")
{
    // The other modes print and always exit 0; this one is in the offline suite, so its verdict has
    // to reach the exit code. Bare returns elsewhere keep the entry point void.
    Environment.ExitCode = await RunFloorAsync();
    return;
}

var outDir = Path.Combine(AppContext.BaseDirectory, "out");
Directory.CreateDirectory(outDir);

var notBefore = DateTimeOffset.UtcNow.AddDays(-3);
var notAfter = DateTimeOffset.UtcNow.AddYears(5);
static byte[] Serial() { var s = RandomNumberGenerator.GetBytes(16); s[0] &= 0x7F; return s; }

X509Certificate2 MakeCa(string cn, X509Certificate2 issuer)
{
    var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
    var req = new CertificateRequest($"CN={cn}", ecdsa, HashAlgorithmName.SHA384);
    req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
    req.CertificateExtensions.Add(new X509KeyUsageExtension(
        X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign, true));
    // TLS-only intermediate, like the emSign "EM * TLS CA - G3x" rows.
    req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
    var pub = issuer == null
        ? req.CreateSelfSigned(notBefore, notAfter)
        : req.Create(issuer, notBefore, notAfter, Serial());
    // A request built from an AsymmetricAlgorithm already carries the key; only a file-loaded CA
    // (the EmSignCa case) needs it attached afterwards.
    return pub.HasPrivateKey ? pub : pub.CopyWithPrivateKey(ecdsa);
}

var root = MakeCa("Probe Root TLS G3", null);
var inter = MakeCa("Probe EM TLS CA - G3B", root);

using var leafKey = RSA.Create(2048);
var leafReq = new CertificateRequest("CN=probe.example", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(
    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
leafReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
var san = new SubjectAlternativeNameBuilder();
san.AddDnsName("probe.example");
leafReq.CertificateExtensions.Add(san.Build());

// The exact CertEngine path: ECDSA CA signing an RSA request needs a signature generator,
// and the issuer name comes from X509Certificate2.SubjectName (X500DistinguishedName).
using var issuerKey = inter.GetECDsaPrivateKey();
var generator = X509SignatureGenerator.CreateForECDsa(issuerKey);
var leafPub = leafReq.Create(inter.SubjectName, generator, notBefore, notAfter, Serial());
X509Certificate2 leaf;
using (var withKey = leafPub.HasPrivateKey ? leafPub : leafPub.CopyWithPrivateKey(leafKey))
{
    // CertEngine round-trips through a PFX with PersistKeySet (Windows 10 1809 needs the key in
    // the keystore for SChannel), so reproduce that here rather than a bare CopyWithPrivateKey.
    var pfx = withKey.Export(X509ContentType.Pfx, "");
    leaf = X509CertificateLoader.LoadPkcs12(pfx, "",
        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
}

File.WriteAllText(Path.Combine(outDir, "root.pem"), root.ExportCertificatePem());
File.WriteAllText(Path.Combine(outDir, "inter.pem"), inter.ExportCertificatePem());
File.WriteAllText(Path.Combine(outDir, "leaf.pem"), leaf.ExportCertificatePem());

Console.WriteLine($"leaf subject={leaf.Subject}");
Console.WriteLine($"leaf issuer  ={leaf.Issuer}");
Console.WriteLine($"inter subject CN via GetNameInfo(SimpleName)='{inter.GetNameInfo(X509NameType.SimpleName, false)}'");

using (var manual = new X509Chain())
{
    manual.ChainPolicy.ExtraStore.Add(inter);
    manual.ChainPolicy.ExtraStore.Add(root);
    manual.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
    manual.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
    manual.ChainPolicy.CustomTrustStore.Add(root);
    var ok = manual.Build(leaf);
    Console.WriteLine($"offline chain build: {ok} elements={manual.ChainElements.Count} status={string.Join("|", manual.ChainStatus.Select(s => s.Status))}");
}

if (mode == "gen") return;

var chainCollection = new X509Certificate2Collection { inter, root };
SslStreamCertificateContext ctx = null;
try
{
    ctx = SslStreamCertificateContext.Create(leaf, chainCollection, offline: true);
    Console.WriteLine($"context: target={ctx.TargetCertificate.Subject} intermediates={ctx.IntermediateCertificates.Count}");
    foreach (var c in ctx.IntermediateCertificates) Console.WriteLine($"   ctx intermediate: {c.Subject}");
}
catch (Exception ex)
{
    Console.WriteLine($"SslStreamCertificateContext.Create FAILED: {ex.GetType().Name}: {ex.Message}");
    if (mode == "context") return;
}

if (mode == "client")
{
    var port = int.Parse(args[1]);
    using var tcp = new TcpClient();
    tcp.Connect(IPAddress.Loopback, port);
    var cs = new SslStream(tcp.GetStream(), false, (_, _, chain, errors) =>
    {
        Console.WriteLine($"  dotnet client sees chainElements={chain?.ChainElements.Count} errors={errors}");
        foreach (var el in chain?.ChainElements ?? Enumerable.Empty<X509ChainElement>())
            Console.WriteLine($"     el: {el.Certificate.Subject}");
        return true;
    });
    try
    {
        await cs.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = "probe.example" });
        Console.WriteLine($"  dotnet client handshake OK, cipher={cs.NegotiatedCipherSuite} tls={cs.SslProtocol}");
    }
    catch (Exception ex) { Console.WriteLine($"  dotnet client failed: {ex.GetType().Name}: {ex.Message}"); }
    return;
}

await ServeOnceAsync(mode == "context" ? ctx : null, leaf);
return;

async Task ServeOnceAsync(SslStreamCertificateContext sctx, X509Certificate2 fallbackLeaf)
{
    var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    Console.WriteLine($"PORT={((IPEndPoint)listener.LocalEndpoint).Port}");
    Console.Out.Flush();

    using var client = await listener.AcceptTcpClientAsync();
    listener.Stop();
    var ssl = new SslStream(client.GetStream(), false);
    var opts = new SslServerAuthenticationOptions
    {
        ClientCertificateRequired = false,
        CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
        ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http11 },
        ServerCertificateContext = sctx,
        ServerCertificate = sctx == null ? fallbackLeaf : null,
    };
    try
    {
        await ssl.AuthenticateAsServerAsync(opts, CancellationToken.None);
        Console.WriteLine($"  server handshake COMPLETED (peer accepted our chain), alpn={ssl.NegotiatedApplicationProtocol}");
        await ssl.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"));
    }
    catch (Exception ex)
    {
        Console.WriteLine($"  server handshake FAILED: {ex.GetType().Name}: {ex.Message}");
    }
    finally { ssl.Dispose(); }
}

async Task ServeEmSignShapeAsync(string certsDir, int port, string shape, int caIndex)
{
    var chainPaths = Directory.GetFiles(Path.Combine(certsDir, "chain")).ToArray();
    var cas = new List<EmSignCa>();
    foreach (var path in Directory.GetFiles(Path.Combine(certsDir, "intermediates")))
    {
        using var probe = X509CertificateLoader.LoadCertificate(File.ReadAllBytes(path));
        var cn = probe.GetNameInfo(X509NameType.SimpleName, false);
        var known = EmSignCa.KnownIntermediates.Where(k => k.Name == cn).ToArray();
        if (known.Length == 0) continue;
        cas.Add(EmSignCa.LoadFromPem(cn, known[0].Scalar, path, chainPaths));
    }

    // A single-element list pins which CA signs, so the wire shape is reproducible per run.
    var engine = new CertEngine(cas[caIndex].CertificateWithKey, new() { cas[caIndex] },
        CertEngineMode.EmSignOnly);
    var issued = engine.GetCert("emsign-test.example");
    var noAnchor = new X509Certificate2Collection();
    var noIntermediate = new X509Certificate2Collection();
    foreach (var c in issued.Chain!)
    {
        if (c.Subject != c.Issuer) noAnchor.Add(c);
        if (c.Subject != issued.Leaf.Issuer) noIntermediate.Add(c);
    }

    var wire = shape switch
    {
        "full" => issued.Chain,
        "no-anchor" => noAnchor,
        "no-intermediate" => noIntermediate,
        "leaf" => null,
        _ => throw new ArgumentException($"unknown shape {shape}")
    };

    Console.WriteLine($"leaf:   {issued.Leaf.Subject}");
    Console.WriteLine($"issuer: {issued.Leaf.Issuer}");
    Console.WriteLine($"on wire: {(wire == null ? "leaf only" : string.Join(" | ", wire.Select(c => c.Subject)))}");

    var listener = new TcpListener(IPAddress.Loopback, port);
    listener.Start();
    Console.WriteLine($"PORT={port} shape={shape} (ctrl-C to stop)");
    Console.Out.Flush();

    while (true)
    {
        using var client = await listener.AcceptTcpClientAsync();
        OpenSslServerStream? ssl = null;
        try
        {
            // MitmProxy has already consumed the ClientHello when it hands the socket over, so the
            // probe reads exactly one record first and replays it; otherwise that hello would be
            // counted as the client's reply.
            var transport = client.GetStream();
            var hello = await ReadOneRecordAsync(transport);
            ssl = await OpenSslServerStream.AcceptAsync(transport, hello,
                issued.Leaf, wire, alpn: null, CancellationToken.None);
            Console.WriteLine($"  peer ACCEPTED, alpn='{ssl.NegotiatedProtocol}'");
            await ssl.WriteAsync(Encoding.ASCII.GetBytes(
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"),
                CancellationToken.None);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  peer REJECTED the wire shape: {ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            ssl?.Dispose();
            client.Dispose();
        }
    }

    static async Task<byte[]> ReadOneRecordAsync(NetworkStream stream)
    {
        var header = new byte[5];
        await stream.ReadExactlyAsync(header);
        var record = new byte[5 + ((header[3] << 8) | header[4])];
        header.CopyTo(record, 0);
        await stream.ReadExactlyAsync(record.AsMemory(5, record.Length - 5));
        return record;
    }
}

// ---- floor: the version floor the libssl terminator actually runs with ----

async Task<int> RunFloorAsync()
{
    var leaf = FloorLeaf();
    var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    var port = ((IPEndPoint)listener.LocalEndpoint).Port;

    // One suite list and one extension set in every row, so the version the hello offers is the only
    // variable between them. TLS_RSA key transport is in the list because it needs no signed
    // ServerKeyExchange, which keeps a SHA-1 question out of the 1.0 and 1.1 rows; the ECDHE suites are
    // what a browser of that era offered, and an RSA 2048 leaf can sign for all of them.
    int[] suites = [0x002f, 0x0035, 0x0033, 0x003c, 0x009c, 0x009e, 0xc013, 0xc014, 0xc02f, 0xc030];
    (int Type, byte[] Body)[] exts =
    [
        (0x0000, HelloBuilder.Sni("probe.example")),
        (0x000a, HelloBuilder.Groups([0x0017, 0x0018, 0x0019])),
        (0x000b, HelloBuilder.PointFormats([0])),
        (0x000d, HelloBuilder.SigAlgs([0x0401, 0x0402, 0x0403, 0x0501, 0x0804, 0x0805])),
    ];
    // A TLS 1.3 hello has to carry a key_share or the server answers with a missing_extension alert and
    // the row says nothing about the version (RFC 8446 section 4.2.8). x25519 is group 0x001d.
    (int Type, byte[] Body)[] tls13 =
    [
        (0x0000, HelloBuilder.Sni("probe.example")),
        (0x000a, HelloBuilder.Groups([0x001d, 0x0017])),
        (0x000b, HelloBuilder.PointFormats([0])),
        (0x000d, HelloBuilder.SigAlgs([0x0403, 0x0804])),
        (0x002b, HelloBuilder.SupportedVersions([0x0304])),
        (0x0033, KeyShare(0x001d, 32)),
    ];

    var rows = new List<(string Label, bool Accepted, string Report)>
    {
        // Every row carries the builder's legacy 0x0301 record header while the handshake body holds the
        // version under test, so the header is constant across the rows; and a refusal is attributed to
        // the version by its own alert number rather than inferred from the difference.
        await CraftedRowAsync(listener, port, leaf, "tls 1.0 hello", HelloBuilder.BuildHello(0x0301, suites, exts)),
        await CraftedRowAsync(listener, port, leaf, "tls 1.1 hello", HelloBuilder.BuildHello(0x0302, suites, exts)),
        await CraftedRowAsync(listener, port, leaf, "tls 1.2 hello", HelloBuilder.BuildHello(0x0303, suites, exts)),
        await CraftedRowAsync(listener, port, leaf, "tls 1.3 hello", HelloBuilder.BuildHello(0x0303, new[] { 0x1301, 0x1302, 0x1303 }, tls13)),
    };

    foreach (var (label, _, report) in rows) Console.WriteLine($"{label,-16} => {report}");

    var real = await SchannelRowAsync(listener, port, leaf);
    Console.WriteLine($"{"real SslStream 1.2",-16} => {real.Report}");

    listener.Stop();

    // The floor is judged in both directions: a client offering 1.2 or 1.3 has to be terminable, and a
    // client offering only 1.0 or 1.1 must not be. The rows are libssl's own answer rather than a
    // version this program asks for, so a library upgrade that moves the floor is caught here.
    var gate = new List<string>();
    if (!Accepted("tls 1.2 hello")) gate.Add("a crafted TLS 1.2 hello was not accepted");
    if (!Accepted("tls 1.3 hello")) gate.Add("a crafted TLS 1.3 hello was not accepted");
    if (Accepted("tls 1.0 hello")) gate.Add("the terminator accepted a hello offering only TLS 1.0");
    if (Accepted("tls 1.1 hello")) gate.Add("the terminator accepted a hello offering only TLS 1.1");
    if (!real.Accepted) gate.Add("a real TLS 1.2 client did not terminate and read the response");
    Console.WriteLine(gate.Count == 0
        ? "floor: ok, 1.2 and 1.3 terminate, 1.0 and 1.1 are refused"
        : "floor: FAIL - " + string.Join("; ", gate));
    return gate.Count == 0 ? 0 : 1;

    bool Accepted(string label) => rows.First(r => r.Label == label).Accepted;
}

async Task<(string Label, bool Accepted, string Report)> CraftedRowAsync(TcpListener listener, int port,
    X509Certificate2 leaf, string label, byte[] hello)
{
    // The terminator runs on its own task because a crafted row stops at the first reply record: only
    // the client side can see the refusal, and only the server side can see libssl's own reason.
    var server = ServeTerminatorAsync(listener, leaf, sendApp: false);
    var accepted = false;
    string reply;
    using (var tcp = new TcpClient())
    {
        try
        {
            await tcp.ConnectAsync(IPAddress.Loopback, port);
            var transport = tcp.GetStream();
            await transport.WriteAsync(hello);
            var (ok, text) = ClassifyReply(await ReadReplyAsync(transport));
            accepted = ok;
            reply = text;
        }
        catch (Exception ex)
        {
            reply = $"raw probe {ex.GetType().Name}: {ex.Message}";
        }
    }   // closing here is what ends the terminator's wait for the client's next record

    return (label, accepted, $"{reply}; {await ServerReportAsync(server)}");
}

async Task<(bool Accepted, string Report)> SchannelRowAsync(TcpListener listener, int port, X509Certificate2 leaf)
{
    var server = ServeTerminatorAsync(listener, leaf, sendApp: true);
    using var tcp = new TcpClient();
    await tcp.ConnectAsync(IPAddress.Loopback, port);
    // This leaf is in no store on purpose, so the callback keeps the chain check from ending the row
    // before termination itself is exercised.
    using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
    try
    {
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = "probe.example",
            EnabledSslProtocols = SslProtocols.Tls12,
        }, CancellationToken.None);
        var response = await DrainAsync(ssl);
        // The body is the gate, not just the handshake: it says the bytes crossed the terminator intact.
        var body = response.Length >= 2 ? Encoding.ASCII.GetString(response[^2..]) : "";
        return (body == "ok", $"tls={ssl.SslProtocol} cipher={ssl.NegotiatedCipherSuite} " +
                      $"read {response.Length} bytes ending '{body}'; {await ServerReportAsync(server)}");
    }
    catch (Exception ex)
    {
        return (false, $"SChannel client {ex.GetType().Name}: {ex.Message}; {await ServerReportAsync(server)}");
    }
}

async Task<string> ServeTerminatorAsync(TcpListener listener, X509Certificate2 leaf, bool sendApp)
{
    using var client = await listener.AcceptTcpClientAsync();
    OpenSslServerStream ssl = null;
    try
    {
        // Nothing is replayed: this probe wrote the hello itself, so the terminator reads it off the
        // transport. emserve replays because MitmProxy has already consumed the hello by then.
        ssl = await OpenSslServerStream.AcceptAsync(client.GetStream(), default, leaf, null,
            alpn: null, CancellationToken.None);
        if (!sendApp) return "handshake completed";
        await ssl.WriteAsync(Encoding.ASCII.GetBytes(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"), CancellationToken.None);
        return "handshake completed, response written";
    }
    catch (Exception ex)
    {
        return $"terminator {ex.GetType().Name}: {ex.Message}";
    }
    finally { ssl?.Dispose(); }
}

static async Task<string> ServerReportAsync(Task<string> server)
{
    // A terminator that never returns is a fault in this probe, not a fact about libssl, so the row
    // closes instead of hanging the suite.
    if (await Task.WhenAny(server, Task.Delay(TimeSpan.FromSeconds(20))) != server) return "terminator still busy after 20 s";
    return await server;
}

// libssl only signs with this certificate, so it is self-signed and trusted by nothing.
static X509Certificate2 FloorLeaf()
{
    using var rsa = RSA.Create(2048);
    var req = new CertificateRequest("CN=probe.example", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
    req.CertificateExtensions.Add(new X509KeyUsageExtension(
        X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
    req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
        new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
    var san = new SubjectAlternativeNameBuilder();
    san.AddDnsName("probe.example");
    req.CertificateExtensions.Add(san.Build());
    var now = DateTimeOffset.UtcNow;
    var made = req.CreateSelfSigned(now.AddDays(-1), now.AddMinutes(10));
    using var withKey = made.HasPrivateKey ? made : made.CopyWithPrivateKey(rsa);
    // Exportable, because AcceptAsync hands OpenSSL the PKCS#8 of GetRSAPrivateKey().
    return X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pfx, ""), "",
        X509KeyStorageFlags.Exportable);
}

// ClientKeyShare with a single entry: the group and a key_exchange of the length that group requires
// (RFC 8446 section 4.2.8). The contents are random, because the row asks only whether the version is
// acceptable, and a server that accepts it goes on to answer with a ServerHello.
static byte[] KeyShare(int group, int keyLength)
{
    var entry = new List<byte> { (byte)(group >> 8), (byte)group, (byte)(keyLength >> 8), (byte)keyLength };
    entry.AddRange(RandomNumberGenerator.GetBytes(keyLength));
    var body = new List<byte> { (byte)(entry.Count >> 8), (byte)entry.Count };
    body.AddRange(entry);
    return [.. body];
}

static async Task<ReadOnlyMemory<byte>> ReadReplyAsync(NetworkStream stream)
{
    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
    var header = new byte[5];
    await stream.ReadExactlyAsync(header, cts.Token);
    var record = new byte[5 + ((header[3] << 8) | header[4])];
    header.CopyTo(record, 0);
    await stream.ReadExactlyAsync(record.AsMemory(5, record.Length - 5), cts.Token);
    return record;
}

static async Task<byte[]> DrainAsync(Stream stream)
{
    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
    var all = new MemoryStream();
    var buffer = new byte[256];
    while (true)
    {
        var n = await stream.ReadAsync(buffer, cts.Token);
        if (n <= 0) break;
        all.Write(buffer, 0, n);
    }
    return all.ToArray();
}

// The first reply record is the whole answer to a crafted hello. Content type 21 is an alert whose
// description names the layer that refused; content type 22 with handshake type 2 is the server's hello,
// which RFC 8446 section 4.1.3 also uses for a HelloRetryRequest by fixing the random.
static (bool Accepted, string Text) ClassifyReply(ReadOnlyMemory<byte> reply)
{
    var r = reply.Span;
    if (r[0] == 0x15 && r.Length >= 7)
        return (false, $"refused with alert level {r[5]} description {AlertName(r[6])}");
    if (r[0] == 0x16 && r.Length >= 11)
    {
        // The hello's own version is at octet 9: 5 record header + 1 handshake type + 3 handshake length.
        // Octets 1 and 2 are the record header's version, which a TLS 1.3 server also fills with 0x0303.
        var version = (r[9] << 8) | r[10];
        return r[5] switch
        {
            0x02 when ServerHello.IsHelloRetryRequest(r) => (true, $"HelloRetryRequest at version 0x{version:x4}"),
            // A passive reader tells our terminator apart from the server it stands in for by this pair,
            // so the row carries them: what the client-facing leg actually put on the wire.
            0x02 => (true, Selection(r, version)),
            var t => (false, $"handshake type {t} at version 0x{version:x4}"),
        };
    }
    return (false, $"content type 0x{r[0]:x2}, {r.Length} bytes");

    static string Selection(ReadOnlySpan<byte> r, int version)
    {
        var at = $"accepted: ServerHello at version 0x{version:x4}";
        // Parse refuses a hello whose message length does not fit the record it came in, so the byte and
        // the declared length are both reported: they separate a short read from a hello this decoder
        // cannot name.
        return ServerHello.Parse(r) is { } selection
            ? $"{at}, JA4S {selection.Ja4S()} JA3S {selection.Ja3S()}"
            : $"{at}, {r.Length} bytes hold a record declaring {((r[3] << 8) | r[4])} {Convert.ToHexString(r)}";
    }
}

// Values and numbers from RFC 5246 section 7.2; anything outside that table is reported as a number.
static string AlertName(int description) => description switch
{
    0 => "close_notify(0)",
    10 => "unexpected_message(10)",
    20 => "bad_record_mac(20)",
    21 => "decryption_failed_RESERVED(21)",
    22 => "record_overflow(22)",
    30 => "decompression_failure(30)",
    40 => "handshake_failure(40)",
    41 => "no_certificate_RESERVED(41)",
    42 => "bad_certificate(42)",
    43 => "unsupported_certificate(43)",
    44 => "certificate_revoked(44)",
    45 => "certificate_expired(45)",
    46 => "certificate_unknown(46)",
    47 => "illegal_parameter(47)",
    48 => "unknown_ca(48)",
    49 => "access_denied(49)",
    50 => "decode_error(50)",
    51 => "decrypt_error(51)",
    60 => "export_restriction_RESERVED(60)",
    70 => "protocol_version(70)",
    71 => "insufficient_security(71)",
    80 => "internal_error(80)",
    90 => "user_canceled(90)",
    100 => "no_renegotiation(100)",
    110 => "unsupported_extension(110)",
    var d => $"description {d}",
};

async Task ServeFiddlerLeafAsync(string host, int port, string variant)
{
    var root = RootCa.GetFiddlerRoot();
    X509Certificate2 leaf;
    if (variant == "served")
    {
        var serving = CrlService.Start(root);
        if (serving == null) { Console.WriteLine("CrlService did not start"); return; }
        // The production path: CertEngine adds the CDP itself, so this also proves the wiring.
        leaf = new CertEngine(root, null, CertEngineMode.FiddlerOnly, serving).GetCert(host).Leaf;
        Console.WriteLine($"  CRL url={serving.Url}");
    }
    else
    {
        leaf = BuildFiddlerLeaf(root, host, variant);
    }
    Console.WriteLine($"leaf subject={leaf.Subject} issuer={leaf.Issuer}");
    File.WriteAllBytes(Path.Combine(AppContext.BaseDirectory, "served-leaf.cer"), leaf.Export(X509ContentType.Cert));
    foreach (var e in leaf.Extensions)
    {
        if (e.Oid.Value == "1.3.6.1.5.5.7.1.1")
            Console.WriteLine("  AIA ocsp=" + string.Join(",",
                new X509AuthorityInformationAccessExtension(e.RawData, e.Critical).EnumerateOcspUris()));
        if (e.Oid.Value == "2.5.29.31")
            Console.WriteLine("  CDP der=" + Convert.ToHexString(e.RawData)
                + " text=" + Encoding.ASCII.GetString(e.RawData).Where(c => c >= 32 && c < 127).Aggregate("", (a, c) => a + c));
    }

    var extras = new X509Certificate2Collection { root };
    Console.WriteLine("--- Windows chain, RevocationMode.NoCheck ---");
    DumpChain(leaf, extras, null);
    Console.WriteLine($"--- Windows chain, RevocationMode.Online ({variant}) ---");
    DumpRevokedChain(leaf, extras);

    var listener = new TcpListener(IPAddress.Loopback, port);
    listener.Start();
    Console.WriteLine($"PORT={port} variant={variant} (ctrl-C to stop)");
    Console.Out.Flush();

    while (true)
    {
        using var client = await listener.AcceptTcpClientAsync();
        var ssl = new SslStream(client.GetStream(), false);
        try
        {
            await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = leaf,
                ClientCertificateRequired = false,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http11 },
            });
            Console.WriteLine($"  peer ACCEPTED the leaf, tls={ssl.SslProtocol} alpn={ssl.NegotiatedApplicationProtocol}");
            await ssl.WriteAsync(Encoding.ASCII.GetBytes(
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  peer REJECTED the leaf: {ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            ssl.Dispose();
            client.Dispose();
        }
    }
}

// The extension set CertEngine puts on a leaf today, plus the revocation pointers under test.
static X509Certificate2 BuildFiddlerLeaf(X509Certificate2 root, string host, string variant)
{
    using var rsa = RSA.Create(2048);
    var req = new CertificateRequest($"CN={host}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
    req.CertificateExtensions.Add(new X509KeyUsageExtension(
        X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
    req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
        new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
    var san = new SubjectAlternativeNameBuilder();
    san.AddDnsName(host);
    req.CertificateExtensions.Add(san.Build());

    // Unreachable on purpose (port 9 is discard), and unique per variant so Windows' URL cache
    // cannot carry one experiment's verdict into the next.
    var dead = $"http://127.0.0.1:9/mitmprobe-{variant}";
    if (variant is "cdp" or "both")
        req.CertificateExtensions.Add(new X509Extension("2.5.29.31", CrlDpDer(dead), false));
    if (variant is "ocsp" or "both")
        req.CertificateExtensions.Add(new X509Extension("1.3.6.1.5.5.7.1.1", AiaDer(dead), false));

    var serial = RandomNumberGenerator.GetBytes(16);
    serial[0] &= 0x7F;
    var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
    var notAfter = DateTimeOffset.UtcNow.AddYears(1);
    if (notAfter > root.NotAfter) notAfter = root.NotAfter - TimeSpan.FromDays(1);

    var pub = req.Create(root, notBefore, notAfter, serial);
    using var withKey = pub.CopyWithPrivateKey(rsa);
    return X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pfx, ""), "",
        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
}

static byte[] CrlDpDer(string url)
{
    var dp = new Asn1Tag(TagClass.ContextSpecific, 0, true);
    var uri = new Asn1Tag(TagClass.ContextSpecific, 6, false);
    var w = new AsnWriter(AsnEncodingRules.DER);
    using (w.PushSequence())                 // CRLDistributionPoints SEQUENCE OF
    {
        using (w.PushSequence())             // DistributionPoint
        {
            using (w.PushSequence(dp))       //   [0] distributionPoint
            {
                using (w.PushSequence(dp))   //     [0] fullName, GeneralNames implicitly tagged
                    w.WriteCharacterString(UniversalTagNumber.IA5String, url, uri);
            }
        }
    }
    return w.Encode();
}

static byte[] AiaDer(string url)
{
    var uri = new Asn1Tag(TagClass.ContextSpecific, 6, false);
    var w = new AsnWriter(AsnEncodingRules.DER);
    using (w.PushSequence())                 // AuthorityInfoAccessSyntax SEQUENCE OF
    {
        using (w.PushSequence())             // AccessDescription
        {
            w.WriteObjectIdentifier("1.3.6.1.5.5.7.48.1");   // id-ad-ocsp
            w.WriteCharacterString(UniversalTagNumber.IA5String, url, uri);
        }
    }
    return w.Encode();
}

static void DumpRevokedChain(X509Certificate2 leaf, X509Certificate2Collection extra)
{
    using var chain = new X509Chain();
    chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
    chain.ChainPolicy.ExtraStore.AddRange(extra);
    var ok = chain.Build(leaf);
    Console.WriteLine($"  build={ok} overall={string.Join("|", chain.ChainStatus.Select(s => $"{s.Status}:{(s.StatusInformation ?? "").Trim()}"))}");
    foreach (var el in chain.ChainElements)
        Console.WriteLine($"    {el.Certificate.Subject}  [{(el.ChainElementStatus.Length == 0 ? "ok" : string.Join("|", el.ChainElementStatus.Select(s => s.Status.ToString())))}]");
}

async Task RunEmSignAsync(string certsDir)
{
    var chainPaths = Directory.GetFiles(Path.Combine(certsDir, "chain")).ToArray();
    var cas = new List<EmSignCa>();
    foreach (var path in Directory.GetFiles(Path.Combine(certsDir, "intermediates")))
    {
        using var probe = X509CertificateLoader.LoadCertificate(File.ReadAllBytes(path));
        var cn = probe.GetNameInfo(X509NameType.SimpleName, false);
        var known = EmSignCa.KnownIntermediates.Where(k => k.Name == cn).ToArray();
        if (known.Length == 0) { Console.WriteLine($"skip (no scalar): {cn}"); continue; }
        cas.Add(EmSignCa.LoadFromPem(cn, known[0].Scalar, path, chainPaths));
    }

    // EmSignOnly never signs with the first argument, so any loaded CA works as the placeholder.
    var engine = new CertEngine(cas[0].CertificateWithKey, cas, CertEngineMode.EmSignOnly);
    var issued = engine.GetCert("emsign-test.example");
    Console.WriteLine($"leaf subject={issued.Leaf.Subject}");
    Console.WriteLine($"leaf issuer ={issued.Leaf.Issuer}");
    Console.WriteLine($"sig alg     ={issued.Leaf.SignatureAlgorithm.Value}");
    Console.WriteLine($"chain       ={(issued.Chain == null ? "NULL" : issued.Chain.Count + " certificates")}");
    if (issued.Chain != null)
        foreach (var c in issued.Chain) Console.WriteLine($"   chain: {c.Subject}");

    var issuedCa = cas.First(c => c.CertificateWithKey.Subject == issued.Leaf.Issuer);
    var extras = new X509Certificate2Collection { issuedCa.CertificateWithKey };
    foreach (var p in chainPaths) extras.Add(X509CertificateLoader.LoadCertificateFromFile(p));

    Console.WriteLine("--- Windows chain, default policy + ExtraStore ---");
    DumpChain(issued.Leaf, extras, null);
    Console.WriteLine("--- Windows chain, custom root trust = emSign ECC Root CA - G3 ---");
    var anchor = extras.FirstOrDefault(c => c.Subject.Contains("emSign ECC Root CA - G3"));
    DumpChain(issued.Leaf, extras, anchor);

    // SChannel refuses to chain the distrusted intermediate, which truncates the context to
    // [intermediate]. SslCertificateTrust hands SChannel an explicit trust list instead of the
    // machine's, so try that to see whether the cross-signed root survives.
    SslStreamCertificateContext best = SslStreamCertificateContext.Create(issued.Leaf, extras, offline: true);
    Console.WriteLine($"context(default) = {best.IntermediateCertificates.Count} intermediates");
    foreach (var c in best.IntermediateCertificates) Console.WriteLine($"   {c.Subject}");
    foreach (var sendInHandshake in new[] { false, true })
    {
        try
        {
            var trustList = new X509Certificate2Collection { anchor };
            var trust = SslCertificateTrust.CreateForX509Collection(trustList, sendInHandshake);
            var alternate = SslStreamCertificateContext.Create(issued.Leaf, extras, offline: true, trust);
            Console.WriteLine($"context(trust, sendInHandshake={sendInHandshake}) = {alternate.IntermediateCertificates.Count} intermediates");
            foreach (var c in alternate.IntermediateCertificates) Console.WriteLine($"   {c.Subject}");
            if (best == null || alternate.IntermediateCertificates.Count > best.IntermediateCertificates.Count)
                best = alternate;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"context(trust, sendInHandshake={sendInHandshake}) FAILED: {ex.GetType().Name}: {ex.Message}");
        }
    }

    // A store-backed trust is the only form Windows supports for "send trust in handshake"; the
    // store is scratch and removed again below.
    const string scratchStoreName = "TlsMitmProbeTrust";
    X509Store scratch = null;
    try
    {
        scratch = new X509Store(scratchStoreName, StoreLocation.CurrentUser);
        scratch.Open(OpenFlags.ReadWrite);
        foreach (var c in scratch.Certificates) scratch.Remove(c);
        scratch.Add(anchor);
        var crossRoot = extras.First(c => c.Subject.Contains("emSign Root TLS CA - G3"));
        scratch.Add(crossRoot);
        var storeTrust = SslCertificateTrust.CreateForX509Store(scratch, sendTrustInHandshake: true);
        var storeCtx = SslStreamCertificateContext.Create(issued.Leaf, extras, offline: true, storeTrust);
        Console.WriteLine($"context(store trust) = {storeCtx.IntermediateCertificates.Count} intermediates");
        foreach (var c in storeCtx.IntermediateCertificates) Console.WriteLine($"   {c.Subject}");
        if (best == null || storeCtx.IntermediateCertificates.Count > best.IntermediateCertificates.Count)
            best = storeCtx;
    }
    catch (Exception ex)
    {
        Console.WriteLine($"context(store trust) FAILED: {ex.GetType().Name}: {ex.Message}");
    }

    try
    {
        await ServeOnceAsync(best, issued.Leaf);
    }
    finally
    {
        if (scratch != null)
        {
            try
            {
                foreach (var c in scratch.Certificates) scratch.Remove(c);
                scratch.Close();
            }
            catch { }
        }
    }
}

static void DumpChain(X509Certificate2 leaf, X509Certificate2Collection extra, X509Certificate2 anchor)
{
    using var chain = new X509Chain();
    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
    chain.ChainPolicy.ExtraStore.AddRange(extra);
    if (anchor != null)
    {
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(anchor);
    }
    var ok = chain.Build(leaf);
    Console.WriteLine($"  build={ok} elements={chain.ChainElements.Count} overall={string.Join("|", chain.ChainStatus.Select(s => s.Status))}");
    foreach (var el in chain.ChainElements)
        Console.WriteLine($"    {el.Certificate.Subject}  [{(el.ChainElementStatus.Length == 0 ? "ok" : string.Join("|", el.ChainElementStatus.Select(s => s.Status)))}]");
}
