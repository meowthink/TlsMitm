using TlsMitm;
using System.Security.Cryptography.X509Certificates;
using System.Text;

const int ProxyPort = 8443;
const string EmSignCertDir = "emsign_certs";

// One file per run: a fixed name truncated the previous run, which is the run whose crash the next
// start is usually asked about. AutoFlush stays on - a native fail-fast never flushes a buffer.
var logPath = Path.Combine(AppContext.BaseDirectory, $"tlsmitm-{DateTime.Now:yyyyMMdd-HHmmss}.log");
var logWriter = new StreamWriter(new FileStream(logPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
{
    AutoFlush = true
};
Console.OutputEncoding = Encoding.UTF8;
Console.SetOut(new TeeWriter(Console.Out, logWriter));
Console.WriteLine($"[Main] Logging to {logPath}");

// Parse command-line arguments
var useEmSign = args.Contains("--emsign") || args.Contains("-e");
var emSignOnly = args.Contains("--emsign-only");
var rotate = args.Contains("--rotate");
var echDowngrade = args.Contains("--no-ech-downgrade") ? null : new EchDowngrade();
var initCa = args.Contains("--init-ca");
var rootPath = Option("--root");
var rootThumbprint = Option("--root-thumbprint");
var pids = ParseInts(Option("--pid"), "--pid");
var includeImages = ParseNames(Option("--process"));
var excludedPids = ParseInts(Option("--exclude-pid"), "--exclude-pid");
var excludedImages = ParseNames(Option("--exclude-process"));

var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    Console.WriteLine("\n[Main] Shutting down...");
    cts.Cancel();
};

Console.WriteLine("[Main] TlsMitm - WinDivert + MITM Proxy (Transparent)");
Console.WriteLine("[Main] Requires: administrator (driver load); a root from --init-ca, --root, or Fiddler");
Console.WriteLine("[Main] Usage: dotnet run [--emsign | --emsign-only | --rotate] [--no-ech-downgrade]");
Console.WriteLine("[Main]                          [--init-ca | --root <pfx> | --root-thumbprint <thumbprint>]");
Console.WriteLine("[Main]                          [--pid <pid,...> | --exclude-pid <pid,...>]");
Console.WriteLine("[Main]                          [--process <exe,...> | --exclude-process <exe,...>]");
Console.WriteLine("[Main]   --emsign      pick the chain per client process (emSign for Node/Electron, Fiddler otherwise)");
Console.WriteLine("[Main]   --emsign-only force the emSign chain for every client");
Console.WriteLine("[Main]   --rotate      rotate between the Fiddler root and the emSign intermediates");
Console.WriteLine("[Main]   --no-ech-downgrade  relay ECH hellos blind instead of terminating them");
Console.WriteLine("[Main]   --init-ca     create a machine-wide root when none is installed (needs elevation)");
Console.WriteLine("[Main]   --root        sign with this PFX (password from TLSMITM_ROOT_PASSWORD)");
Console.WriteLine("[Main]   --pid / --process  intercept only these client processes (pid or executable)");
Console.WriteLine("[Main]   --exclude-pid / --exclude-process  intercept everything except these client processes");
Console.WriteLine();

X509Certificate2 rootCa;
if (initCa)
    rootCa = RootCa.CreateAndInstall();
else if (rootPath != null)
    rootCa = RootCa.LoadFromPfx(rootPath, Environment.GetEnvironmentVariable("TLSMITM_ROOT_PASSWORD"));
else if (rootThumbprint != null)
    rootCa = RootCa.FindByThumbprint(rootThumbprint);
else
    rootCa = RootCa.GetFiddlerRoot();

// Node and Electron never read the Windows store, so a Node client needs this root as a PEM. It has
// to be exactly the root that signs the leaves: four same-subject Fiddler roots are installed here,
// and a bundle holding more than the right one makes BoringSSL pick a wrong key and fail with
// CERT_SIGNATURE_FAILURE instead of simply trusting it. Point NODE_EXTRA_CA_CERTS at this file.
var activeRootPem = Path.Combine(AppContext.BaseDirectory, "fiddler-root-active.pem");
File.WriteAllText(activeRootPem, rootCa.ExportCertificatePem());
Console.WriteLine($"[Main] Root for Node clients: {activeRootPem} ({rootCa.Thumbprint})");
List<EmSignCa> emSignCas = new();
var mode = CertEngineMode.FiddlerOnly;

if (useEmSign || emSignOnly || rotate)
{
    emSignCas = LoadEmSignCas();
    
    if (emSignOnly)
        mode = CertEngineMode.EmSignOnly;
    else if (rotate)
        mode = CertEngineMode.Rotate;
    else
        mode = CertEngineMode.Auto; // --emsign: emSign only for clients that trust it, Fiddler for the rest
}
else
{
    Console.WriteLine("[Main] emSign support disabled (use --emsign to enable)");
}

// Revocation has to be answerable before a strict client will accept a forged leaf. The CRL is
// signed by the same root and served from loopback, so it needs no DNS and no external host.
using var crl = CrlService.Start(rootCa);
var certEngine = new CertEngine(rootCa, emSignCas, mode, crl);

using var redirector = new PacketRedirector(ProxyPort,
    new ProcessFilter(pids, includeImages, excludedPids, excludedImages));
// Loopback traffic is captured too, so the CRL endpoint needs both halves: RegisterExemption covers
// its replies (matched by source port), RegisterLocalService covers a validator's GET to it, whose
// source port is ephemeral and would otherwise be forward-swapped into the proxy.
if (crl != null)
{
    redirector.RegisterExemption(crl.Port);
    redirector.RegisterLocalService(crl.Port);
}
using var quicBlocker = new QuicBlocker();
var proxy = new MitmProxy(certEngine, redirector, ProxyPort, echDowngrade);

var redirectorTask = redirector.StartAsync();
var quicBlockerTask = quicBlocker.StartAsync();
var proxyTask = proxy.StartAsync(cts.Token);

Console.WriteLine("[Main] Ready. Press Ctrl+C to stop.");
Console.WriteLine("[Main] All outbound TCP traffic will be intercepted.");
Console.WriteLine("[Main] QUIC/UDP port 443 will be blocked (forces HTTP/2 fallback).");
if (echDowngrade != null)
    Console.WriteLine("[Main] ECH downgrade on (default): ECH hellos are terminated; a host that yields no data and no plaintext retry returns to blind relay.");
else
    Console.WriteLine("[Main] ECH downgrade off (--no-ech-downgrade): ECH hellos are relayed blind.");
Console.WriteLine();

try
{
    await Task.Delay(Timeout.Infinite, cts.Token);
}
catch (OperationCanceledException)
{
}

Console.WriteLine("[Main] Stopping...");

List<EmSignCa> LoadEmSignCas()
{
    var cas = new List<EmSignCa>();
    var baseDir = Path.Combine(AppContext.BaseDirectory, EmSignCertDir);
    var interDir = Path.Combine(baseDir, "intermediates");
    var chainDir = Path.Combine(baseDir, "chain");

    if (!Directory.Exists(interDir))
    {
        Console.WriteLine($"[Main] emSign intermediate directory '{interDir}' not found");
        return cas;
    }

    var chainPaths = Directory.Exists(chainDir)
        ? Directory.GetFiles(chainDir).Where(IsCertFile).ToArray()
        : Array.Empty<string>();

    // Select by the CN inside each certificate, never by filename: one CN exists both as a native and
    // as an AAA cross-certificate, so a naming convention here would silently load the wrong one.
    var byName = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    foreach (var path in Directory.GetFiles(interDir))
    {
        if (!IsCertFile(path)) continue;
        try
        {
            using var probe = X509CertificateLoader.LoadCertificate(File.ReadAllBytes(path));
            var cn = probe.GetNameInfo(X509NameType.SimpleName, false);
            if (cn != null) byName.TryAdd(cn, path);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Main] Skipping {Path.GetFileName(path)}: {ex.Message}");
        }
    }

    foreach (var (name, scalar) in EmSignCa.KnownIntermediates)
    {
        if (!byName.TryGetValue(name, out var path)) continue;
        try
        {
            cas.Add(EmSignCa.LoadFromPem(name, scalar, path, chainPaths));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Main] Failed to load {name}: {ex.Message}");
        }
    }

    if (cas.Count > 0)
        Console.WriteLine($"[Main] Loaded {cas.Count} emSign intermediate CAs with {chainPaths.Length} chain certs");
    else
        Console.WriteLine($"[Main] No emSign certificates found in {interDir}");

    return cas;
}

static bool IsCertFile(string path) =>
    Path.GetExtension(path).ToLowerInvariant() is ".pem" or ".crt" or ".cer" or ".der";

// Flags are still hand-parsed: the project ships no NuGet dependencies and needs no completion, so a
// table-driven parser with one lookup per option is the whole requirement.
string? Option(string name)
{
    var at = Array.IndexOf(args, name);
    if (at < 0) return null;
    if (at + 1 >= args.Length || args[at + 1].StartsWith("--", StringComparison.Ordinal))
    {
        Console.WriteLine($"[Main] {name} needs a value");
        Environment.Exit(2);
    }
    return args[at + 1];
}

static string[] ParseNames(string? text) =>
    text == null
        ? Array.Empty<string>()
        : text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(name => name.Length > 0)
            .ToArray();

static int[] ParseInts(string? text, string name)
{
    if (text == null) return Array.Empty<int>();
    var values = new List<int>();
    foreach (var part in text.Split(',', StringSplitOptions.RemoveEmptyEntries))
    {
        if (!int.TryParse(part, out var value))
        {
            Console.WriteLine($"[Main] {name}: '{part}' is not a process id");
            Environment.Exit(2);
        }
        values.Add(value);
    }
    return values.ToArray();
}

sealed class TeeWriter : TextWriter
{
    private readonly TextWriter _console;
    private readonly TextWriter _file;

    public TeeWriter(TextWriter console, TextWriter file)
    {
        _console = console;
        _file = file;
    }

    public override Encoding Encoding { get; } = Encoding.UTF8;

    public override void Write(char value) { _console.Write(value); _file.Write(value); }
    public override void Write(string? value) { _console.Write(value); _file.Write(value); }

    // A clock is what turns a list of resets into a story: only the spacing between a hello and its
    // abort says whether the client retried immediately or held the socket open first.
    public override void WriteLine(string? value)
    {
        var line = $"{DateTime.Now:HH:mm:ss.fff} {value}";
        _console.WriteLine(line);
        _file.WriteLine(line);
    }

    public override void WriteLine() { _console.WriteLine(); _file.WriteLine(); }
    public override void Flush() { _console.Flush(); _file.Flush(); }
}
