using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TlsMitm;

// Scratch probe, not part of the offline suite: does a client that refuses the flight really leave
// an *_aborted.pcap behind, on the leg the live rejections take? The offline handshake-abort mode
// cannot answer that because ClientProcess.Identify has no loopback branch - its in-process client
// is classified as "no known bundling" and gets the Fiddler/SChannel leg, where the refusal arrives
// after AuthenticateAsServerAsync returns and the tee has stopped. Here the client is a separate
// process, so it is classified as node.exe and served an emSign chain through the libssl leg.

var emSignDir = @"C:\Users\meowthink\Documents\Qoder\2026-10-21\5b98d87e\TlsMitm\emsign_certs";
var cas = new List<EmSignCa>();
var chainPaths = Directory.GetFiles(Path.Combine(emSignDir, "chain"));
foreach (var path in Directory.GetFiles(Path.Combine(emSignDir, "intermediates")))
{
    using var probe = X509CertificateLoader.LoadCertificate(File.ReadAllBytes(path));
    var cn = probe.GetNameInfo(X509NameType.SimpleName, false);
    var known = EmSignCa.KnownIntermediates.FirstOrDefault(k => k.Name == cn);
    if (known.Name == null) continue;
    cas.Add(EmSignCa.LoadFromPem(cn!, known.Scalar, path, chainPaths));
}
Console.WriteLine($"[abortcheck] {cas.Count} emSign intermediates");

// A listener nobody hands TLS to: the proxy's upstream socket only has to exist, and with no ALPN
// offered the client leg runs first, so it never speaks on it.
var sink = new TcpListener(IPAddress.Loopback, 0);
sink.Start();

var proxyPort = FreePort();
var engine = new CertEngine(RootCa.GetFiddlerRoot(), cas, CertEngineMode.EmSignOnly);
using var cts = new CancellationTokenSource();
_ = new MitmProxy(engine, new FixedRedirector(IPAddress.Loopback, ((IPEndPoint)sink.LocalEndpoint).Port),
    proxyPort).StartAsync(cts.Token);

var js = Path.Combine(Path.GetTempPath(), $"strict-refuse-{Environment.ProcessId}.js");
// A valid but unrelated CA: `ca` replaces the bundled roots, so the refusal is the client's own doing
// and no store or Node version can make it accept.
using var foreignKey = RSA.Create(2048);
var foreign = new CertificateRequest("CN=abortcheck-foreign", foreignKey, HashAlgorithmName.SHA256,
    RSASignaturePadding.Pkcs1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
var foreignPem = Path.Combine(Path.GetTempPath(), $"abortcheck-foreign-{Environment.ProcessId}.pem");
File.WriteAllText(foreignPem, $"-----BEGIN CERTIFICATE-----\n{Convert.ToBase64String(foreign.RawData, Base64FormattingOptions.InsertLineBreaks)}\n-----END CERTIFICATE-----\n");

File.WriteAllText(js, """
    const tls = require('tls');
    const fs = require('fs');
    const s = tls.connect({ host: '127.0.0.1', port: parseInt(process.argv[2], 10),
                            servername: 'abortcheck.test', ca: fs.readFileSync(process.argv[3], 'utf8'),
                            rejectUnauthorized: true },
      () => { console.log('COMPLETED'); s.destroy(); });
    s.on('error', e => { console.log('refused: ' + (e.code || e.message)); process.exit(0); });
    setTimeout(() => { console.log('TIMEOUT'); process.exit(2); }, 10000);
    """);

var electron = Environment.GetEnvironmentVariable("TLSMITM_ELECTRON")
    ?? @"C:\Users\meowthink\AppData\Local\Programs\Qoder CN\Qoder CN.exe";
var nodeExe = Environment.GetEnvironmentVariable("TLSMITM_NODE");
var useElectron = nodeExe == null && File.Exists(electron);
var clientExe = nodeExe ?? (useElectron ? electron : "node");
Console.WriteLine($"[abortcheck] client executable: {clientExe} ({(useElectron ? "electron" : "node")})");

var psi = new ProcessStartInfo(clientExe, $"\"{js}\" {proxyPort} \"{foreignPem}\"")
{ RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
if (useElectron) psi.Environment["ELECTRON_RUN_AS_NODE"] = "1";
var p = Process.Start(psi)!;
var stdout = await p.StandardOutput.ReadToEndAsync();
var stderr = await p.StandardError.ReadToEndAsync();
await p.WaitForExitAsync();
Console.WriteLine($"[abortcheck] client said: {stdout.Trim()} {stderr.Trim()}");

for (var i = 0; i < 60; i++)
{
    var files = Directory.Exists("captures") ? Directory.GetFiles("captures", "*_aborted.pcap") : Array.Empty<string>();
    if (files.Length > 0)
    {
        Console.WriteLine($"[abortcheck] OK: {files[0]} ({new FileInfo(files[0]).Length} bytes)");
        return 0;
    }
    await Task.Delay(200);
}
Console.WriteLine("[abortcheck] FAIL: no *_aborted.pcap was written");
return 1;

static int FreePort()
{
    var l = new TcpListener(IPAddress.Loopback, 0);
    l.Start();
    var port = ((IPEndPoint)l.LocalEndpoint).Port;
    l.Stop();
    return port;
}

sealed class FixedRedirector(IPAddress ip, int port) : IRedirector
{
    public OriginalDest? LookupOriginalDest(IPAddress deliveredTo, int token, IPAddress serverAddr)
        => new OriginalDest(ip, port, deliveredTo, token);
    public void ReleaseFlow(int token) { }
    public void RegisterExemption(int sourcePort) { }
    public void UnregisterExemption(int sourcePort) { }
    public void RegisterFlowExemption(int sourcePort, IPAddress destination, int destinationPort) { }
    public void UnregisterFlowExemption(int sourcePort, IPAddress destination, int destinationPort) { }
    public void RegisterLocalService(int dstPort) { }
}
