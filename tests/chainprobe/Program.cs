// Two questions:
//  1. synthetic chain: when a leaf is signed by an ECDSA intermediate that is in NO local store,
//     does SslStream put the intermediate + root on the wire? Compares ServerCertificate against
//     ServerCertificateContext.
//  2. "emsign <certsDir>": the same question for the real emSign intermediates, recovered scalars
//     and cross-signed root driving the real CertEngine/EmSignCa from TlsMitm. Serves one
//     connection so a strict Node client using its DEFAULT store can render the verdict.
using System.Net;
using System.Formats.Asn1;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
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
