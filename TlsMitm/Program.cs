using TlsMitm;
using System.Security.Cryptography.X509Certificates;
using System.Text;

const int ProxyPort = 8443;
const string EmSignCertDir = "emsign_certs";
// The name the README's manual instruction uses too, so a rule made by hand and a rule made by
// --allow-relay-in are the same object to this program.
const string RelayRuleName = "tlsmitm-relay-in";

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
var lanText = Option("--lan");
var allowRelayIn = args.Contains("--allow-relay-in");
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
Console.WriteLine("[Main]                          [--lan <ipv4> [--allow-relay-in]]");
Console.WriteLine("[Main]   --emsign      pick the chain per client process; a client with no PID gets emSign");
Console.WriteLine("[Main]   --emsign-only force the emSign chain for every client");
Console.WriteLine("[Main]   --rotate      rotate between the Fiddler root and the emSign intermediates");
Console.WriteLine("[Main]   --no-ech-downgrade  relay ECH hellos blind instead of terminating them");
Console.WriteLine("[Main]   --init-ca     create a machine-wide root when none is installed (needs elevation)");
Console.WriteLine("[Main]   --root        sign with this PFX (password from TLSMITM_ROOT_PASSWORD)");
Console.WriteLine("[Main]   --pid / --process  intercept only these client processes (pid or executable)");
Console.WriteLine("[Main]   --exclude-pid / --exclude-process  intercept everything except these client processes");
Console.WriteLine("[Main]   --lan         also intercept TCP forwarded to clients on this address's subnet");
Console.WriteLine("[Main]   --allow-relay-in  add the inbound allow rule the relay port needs for --lan, and remove it on exit");
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

    // --emsign decides per client from its PID, and a client with no PID - every forwarded LAN one -
    // gets emSign, which is what --emsign-only gives everyone.
    if (emSignOnly)
        mode = CertEngineMode.EmSignOnly;
    else if (rotate)
        mode = CertEngineMode.Rotate;
    else
        mode = CertEngineMode.Auto;
}
else
{
    Console.WriteLine("[Main] emSign support disabled (use --emsign to enable)");
}

// Revocation has to be answerable before a strict client will accept a forged leaf. The CRL is
// signed by the same root and served from loopback, so it needs no DNS and no external host.
using var crl = CrlService.Start(rootCa);
var certEngine = new CertEngine(rootCa, emSignCas, mode, crl);

LanSide? lan = null;
if (lanText != null)
{
    lan = LanSide.Resolve(lanText);
    if (lan == null) Environment.Exit(2);
}

var scope = new ProcessFilter(pids, includeImages, excludedPids, excludedImages);
// The scope is read out of this machine's process table, and a client that is not on this machine has
// no row there. Say it before anything starts capturing, so a scope never looks like it also limits
// what --lan takes in.
if (lan != null && scope.IsActive)
    Console.WriteLine("[Main] Scope names processes on this machine only: a flow forwarded from the LAN has none, so --lan traffic is intercepted whatever --pid/--process say");
// Where a redirected connection lands: the swap turns it into an inbound connection to this host's own
// relay port whose peer address is the server the client asked for. Windows filters inbound and does not
// filter loopback, which is why a local client keeps working while every forwarded one stops before the
// first byte. The probe below asks the stack whether that filter is up; the rule store is only asked to
// hold the rule this run names, never to decide reachability.
var relayRuleOwned = false;
if (lan != null)
{
    Console.WriteLine($"[Main] Firewall: {InboundFirewall.EnabledState()}");
    if (InboundFirewall.Exists(RelayRuleName))
        Console.WriteLine($"[Main] '{RelayRuleName}' is already in the store; left in place, and not removed on exit");
    else if (allowRelayIn)
    {
        relayRuleOwned = InboundFirewall.Add(RelayRuleName,
            "Inbound connections to TlsMitm's relay port, which a redirected flow reaches from its server's address",
            InboundFirewall.ProtoTcp, ProxyPort.ToString());
        Console.WriteLine(relayRuleOwned
            ? $"[Main] Added '{RelayRuleName}' for TCP {ProxyPort}; removed when this run ends"
            : $"[Main] --allow-relay-in did not put '{RelayRuleName}' in the store (needs elevation)");
    }
}
else if (allowRelayIn)
{
    Console.WriteLine("[Main] --allow-relay-in concerns a client that is not this machine, so nothing is added without --lan");
}

using var redirector = new PacketRedirector(ProxyPort, scope, lan);
// Loopback traffic is captured too, so the CRL endpoint needs both halves: RegisterExemption covers
// its replies (matched by source port), RegisterLocalService covers a validator's GET to it, whose
// source port is ephemeral and would otherwise be forward-swapped into the proxy.
if (crl != null)
{
    redirector.RegisterExemption(crl.Port);
    redirector.RegisterLocalService(crl.Port);
}
using var quicBlocker = new QuicBlocker(lan);
var proxy = new MitmProxy(certEngine, redirector, ProxyPort, echDowngrade);

var redirectorTask = redirector.StartAsync();
var quicBlockerTask = quicBlocker.StartAsync();
var proxyTask = proxy.StartAsync(cts.Token);

Console.WriteLine("[Main] Ready. Press Ctrl+C to stop.");
Console.WriteLine("[Main] All outbound TCP traffic will be intercepted.");
Console.WriteLine("[Main] QUIC is dropped by its packet signature, on any port (forces HTTP/2 fallback).");
if (lan != null)
{
    Console.WriteLine($"[Main] LAN capture on {lan.Address}: TCP forwarded from {lan.Network}..{lan.Last} is intercepted,");
    Console.WriteLine("[Main] and UDP forwarded from the same range is captured to drop QUIC. IPv4 forwarding must be on");
    Console.WriteLine("[Main] for that interface (Router --enable-forwarding); DHCP and DNS stay with Router.");
    if (!useEmSign && !emSignOnly && !rotate)
    {
        // A forwarded client is never in this machine's TCP table, so its chain cannot be chosen by
        // process; --emsign is what decides it.
        Console.WriteLine("[Main] This engine serves the Fiddler root to every client; run with --emsign to give a client");
        Console.WriteLine("[Main] with no PID here the emSign chain instead.");
    }
}
if (echDowngrade != null)
    Console.WriteLine("[Main] ECH downgrade on (default): ECH hellos are terminated; a host is relayed blind for 10 min once a terminated session's client leg fails.");
else
    Console.WriteLine("[Main] ECH downgrade off (--no-ech-downgrade): ECH hellos are relayed blind.");
Console.WriteLine();

// One SYN toward the relay from inside the LAN subnet, then the row the stack leaves for it in its own
// TCP table. This is the only reading that settles the question the policy leaves open: an allow rule can
// be in the store and still be outranked by a block rule, and a port nothing names can still be covered by
// a pre-defined rule whose own port field reads as a wildcard.
if (lan != null)
{
    var token = redirector.InjectRelayProbe(lan.ProbeAddress);
    if (token == 0)
    {
        Console.WriteLine("[Main] inbound probe not sent, so whether a remote SYN reaches the relay port is unknown;");
        Console.WriteLine("[Main]   a forwarded client may still be filtered, and a local one never is");
    }
    else
    {
        var answered = false;
        var read = false;
        for (var tick = 0; tick < 15 && !answered; tick++)
        {
            await Task.Delay(100);
            if (RelayProbe.ReadTcpTable() is not { } table) continue;
            read = true;
            answered = RelayProbe.Answers(table, lan.ProbeAddress, token, lan.Address,
                unchecked((ushort)ProxyPort));
        }

        if (answered)
        {
            Console.WriteLine("[Main] inbound probe: the relay port has a half-open row for a SYN from outside this host,");
            Console.WriteLine("[Main]   so a forwarded client reaches the listener");
        }
        else if (!read)
        {
            Console.WriteLine("[Main] inbound probe sent, but the connection table could not be read, so whether that SYN");
            Console.WriteLine("[Main]   reached the relay port is unknown; the run continues as if it had");
        }
        else
        {
            Console.WriteLine("[Main] inbound probe: no half-open row, so the SYN never reached a listener on the relay port.");
            Console.WriteLine("[Main]   Every forwarded client would stop before its first byte, while a local client keeps");
            Console.WriteLine("[Main]   working (loopback is not filtered), which is what makes the two look unrelated.");
            var blocks = InboundFirewall.BlockCandidates(InboundFirewall.ProtoTcp, ProxyPort);
            foreach (var name in blocks.Take(5))
                Console.WriteLine($"[Main]   block rule that could outrank an allow here: {name}");
            if (blocks.Count > 5)
                Console.WriteLine($"[Main]   ... {blocks.Count - 5} more enabled inbound block rules could cover this port");
            if (InboundFirewall.Exists(RelayRuleName))
                Console.WriteLine($"[Main]   '{RelayRuleName}' is in the store and the port stays filtered, so this run ends");
            else
            {
                Console.WriteLine($"[Main]   Add it with: New-NetFirewallRule -DisplayName '{RelayRuleName}' -Direction Inbound");
                Console.WriteLine($"[Main]                  -Protocol TCP -LocalPort {ProxyPort} -Action Allow -Profile Any");
                Console.WriteLine("[Main]   or re-run with --allow-relay-in (needs elevation, removed again when the run ends).");
            }
            if (relayRuleOwned)
            {
                InboundFirewall.Remove(RelayRuleName);
                relayRuleOwned = false;
            }
            return 1;
        }
    }
}

try
{
    await Task.Delay(Timeout.Infinite, cts.Token);
}
catch (OperationCanceledException)
{
}

Console.WriteLine("[Main] Stopping...");
if (relayRuleOwned)
{
    InboundFirewall.Remove(RelayRuleName);
    Console.WriteLine($"[Main] '{RelayRuleName}' removed with it; the port is filtered inbound again");
}

return 0;

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
