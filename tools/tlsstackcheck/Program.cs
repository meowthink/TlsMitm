using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;

// The TLS stack that sits under the proxy's SChannel legs, asked directly instead of inferred from what
// a run did. Three questions, one mode each: what the operating system's protocol policy says, which
// knobs SslStream passes down instead of refusing, and what two SslStream legs on this machine can
// actually agree on. `assert` is the same questions with pass/fail, and only for the answers the proxy
// depends on; the rest is a report, because a host is allowed to disable a protocol.
// A version this stack does not have can leave a leg waiting for an alert that never arrives, so each
// leg gets this clock and the row reports the wait instead of becoming one.
const int HandshakeLimitMs = 10_000;

if (args.Length == 0)
{
    Policy();
    await KnobsAsync();
    await VersionsAsync();
    return 0;
}
switch (args[0])
{
    case "policy": Policy(); return 0;
    case "knobs": await KnobsAsync(); return 0;
    case "versions": await VersionsAsync(); return 0;
    case "assert": return await AssertAsync();
    default: Console.WriteLine(usage()); return 1;
}

static string usage() => "usage: tlsstackcheck [policy|knobs|versions|assert]";

static string Header() =>
    $"host: {RuntimeInformation.OSDescription} | runtime: {RuntimeInformation.FrameworkDescription}";

// ---- policy ----

static void Policy()
{
    Console.WriteLine($"\n== policy == {Header()}");
    // SChannel's per-protocol policy. A version with no key here is on its build default, and the
    // registry cannot name that default, so this is read next to the versions matrix, not instead of it.
    const string tree = @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols";
    using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default).OpenSubKey(tree);
    if (root is null) { Console.WriteLine($"{tree}: absent"); return; }

    var asked = new[] { "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3" };
    var present = root.GetSubKeyNames();
    foreach (var version in asked.Concat(present.Where(n => !asked.Contains(n, StringComparer.Ordinal))
                     .OrderBy(n => n, StringComparer.Ordinal)))
    {
        var parts = new List<string>();
        foreach (var role in new[] { "Client", "Server" })
        {
            using var roleKey = root.OpenSubKey($@"{version}\{role}");
            if (roleKey is not null) parts.Add($"{role} {Values(roleKey)}");
        }
        Console.WriteLine($"{version,-10} {(parts.Count > 0 ? string.Join(" | ", parts)
            : present.Contains(version, StringComparer.Ordinal) ? "key with no Client or Server subkey"
            : "no key: build default")}");
    }
}

static string Values(RegistryKey key)
{
    var names = key.GetValueNames().OrderBy(n => n, StringComparer.Ordinal).ToArray();
    if (names.Length == 0) return "(no values)";
    return string.Join(" ", names.Select(n =>
        $"{n}={key.GetValue(n, null, RegistryValueOptions.DoNotExpandEnvironmentNames)}"));
}

// ---- knobs ----

// Option validation happens before the first byte leaves the process, so a peer that never answers is
// enough to see which knobs the stack refuses outright. "accepted" means the option reached the
// handshake; whether a real server would honour it is the versions matrix' business.
static async Task<int> KnobsAsync()
{
    Console.WriteLine("\n== knobs (SslStream options the stack takes) ==");
    using var fixture = BuildFixture();

    // CipherSuitesPolicy is annotated unsupported on Windows, which is the answer this tool exists to
    // read out rather than a mistake to fix, so the analyzer is quiet for these two call sites.
#pragma warning disable CA1416
    var clientKnobs = new (string Label, Action<SslClientAuthenticationOptions> Set)[]
    {
        ("client TargetHost", o => o.TargetHost = "probe.example"),
        ("client TargetHost=null", o => o.TargetHost = null!),
        ("client EnabledSslProtocols 1.2|1.3", o => o.EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13),
        ("client ApplicationProtocols h2,h/1.1", o => o.ApplicationProtocols =
            [SslApplicationProtocol.Http2, SslApplicationProtocol.Http11]),
        ("client validation callback", o => o.RemoteCertificateValidationCallback = (_, _, _, _) => true),
        ("client revocation Offline", o => o.CertificateRevocationCheckMode = X509RevocationMode.Offline),
        ("client ClientCertificates", o => o.ClientCertificates = [fixture.Leaf]),
        ("client AllowTlsResume=false", o => o.AllowTlsResume = false),
        ("client AllowRsaPssPadding=false", o => o.AllowRsaPssPadding = false),
        ("client AllowRsaPkcs1Padding=false", o => o.AllowRsaPkcs1Padding = false),
        ("client EncryptionPolicy=Require", o => o.EncryptionPolicy = EncryptionPolicy.RequireEncryption),
        ("client CertificateChainPolicy", o => o.CertificateChainPolicy = new X509ChainPolicy()),
        ("client CipherSuitesPolicy", o => o.CipherSuitesPolicy = new CipherSuitesPolicy(
            [TlsCipherSuite.TLS_AES_128_GCM_SHA256, TlsCipherSuite.TLS_AES_256_GCM_SHA384])),
    };
    foreach (var (label, set) in clientKnobs)
        Console.WriteLine($"{label,-32} => {await TryClientAsync(set)}");

    // Each row starts from the set the proxy's server leg uses, and may take something out of it: the
    // interesting answers include the rows that leave the baseline certificate behind.
    var serverKnobs = new (string Label, Func<SslServerAuthenticationOptions, SslServerAuthenticationOptions> Set)[]
    {
        ("server persisted-key certificate", o => o),
        ("server selection callback alone", o =>
        { o.ServerCertificate = null; o.ServerCertificateSelectionCallback = (_, _) => fixture.Leaf; return o; }),
        ("server callback plus certificate", o =>
        { o.ServerCertificateSelectionCallback = (_, _) => fixture.Leaf; return o; }),
        ("server EnabledSslProtocols 1.2|1.3", o =>
        { o.EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13; return o; }),
        ("server ApplicationProtocols h2", o =>
        { o.ApplicationProtocols = [SslApplicationProtocol.Http2]; return o; }),
        ("server ClientCertificateRequired", o => { o.ClientCertificateRequired = true; return o; }),
        ("server revocation Offline", o => { o.CertificateRevocationCheckMode = X509RevocationMode.Offline; return o; }),
        ("server AllowTlsResume=false", o => { o.AllowTlsResume = false; return o; }),
        ("server CipherSuitesPolicy", o => { o.CipherSuitesPolicy = new CipherSuitesPolicy(
            [TlsCipherSuite.TLS_AES_128_GCM_SHA256, TlsCipherSuite.TLS_AES_256_GCM_SHA384]); return o; }),
    };
    foreach (var (label, set) in serverKnobs)
        Console.WriteLine($"{label,-32} => {await TryServerAsync(fixture, set)}");
#pragma warning restore CA1416

    Console.WriteLine("(the fixture certificate is built in memory and never installed anywhere; a row that");
    Console.WriteLine("merely stalls says the option was taken, not that a peer would honour it)");
    return 0;
}

/// <summary>The options the proxy's SChannel server leg always carries.</summary>
static SslServerAuthenticationOptions Baseline(Fixture fixture) => new()
{
    ServerCertificate = fixture.Leaf,
    ClientCertificateRequired = false,
    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
};

static async Task<string> TryClientAsync(Action<SslClientAuthenticationOptions> set)
{
    using var stall = new Stall();
    try
    {
        var options = new SslClientAuthenticationOptions { TargetHost = "probe.example" };
        set(options);
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, stall.Port);
        using var ssl = new SslStream(tcp.GetStream(), false);
        return await Outcome(() => ssl.AuthenticateAsClientAsync(options, stall.Token));
    }
    catch (Exception ex) { return Describe(ex); }
}

static async Task<string> TryServerAsync(Fixture fixture,
    Func<SslServerAuthenticationOptions, SslServerAuthenticationOptions> set)
{
    using var stall = new Stall();
    try
    {
        var options = set(Baseline(fixture));
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, stall.Port);
        using var ssl = new SslStream(tcp.GetStream(), false);
        // The peer here is a plain socket, so nothing answers the ServerHello. A knob the stack cannot
        // honour is thrown before that; anything else is the stall.
        return await Outcome(() => ssl.AuthenticateAsServerAsync(options, stall.Token));
    }
    catch (Exception ex) { return Describe(ex); }
}

static async Task<string> Outcome(Func<Task> handshake)
{
    var task = handshake();
    var finished = await Task.WhenAny(task, Task.Delay(1500));
    if (finished != task) return "accepted (stalled waiting for the peer)";
    try
    {
        await task;
    }
    catch (Exception ex)
    {
        return Describe(ex);
    }
    return "accepted (completed against a socket that never answered)";
}

// ---- versions ----

static async Task VersionsAsync()
{
    Console.WriteLine("\n== versions (loopback pair, one SslStream leg each) ==");
    using var fixture = BuildFixture();
    var rows = new (string Label, SslProtocols Allowed)[]
    {
        ("1.0", SslProtocols.Tls),
        ("1.1", SslProtocols.Tls11),
        ("1.2", SslProtocols.Tls12),
        ("1.3", SslProtocols.Tls13),
        ("1.2|1.3", SslProtocols.Tls12 | SslProtocols.Tls13),
    };
    foreach (var (label, allowed) in rows)
        Console.WriteLine($"{label,-14} => {await NegotiateAsync(allowed, fixture.Leaf)}");
    Console.WriteLine($"{"1.2/1.3 legs",-14} => {await NegotiateAsync(SslProtocols.Tls12, fixture.Leaf, SslProtocols.Tls13)}");
    // A key that stays in this process is the case the product's PFX round trip avoids. The knob probe
    // cannot see it — the stall means the private key is never touched — so this leg pair has to be real.
    Console.WriteLine($"{"1.2 ephemeral",-14} => {await NegotiateAsync(SslProtocols.Tls12, fixture.Ephemeral)}");
}

static async Task<string> NegotiateAsync(SslProtocols clientAllowed, X509Certificate2 certificate,
    SslProtocols? serverAllowed = null)
{
    var server = serverAllowed ?? clientAllowed;
    using var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    var accept = listener.AcceptTcpClientAsync();

    var serverLeg = Task.Run(async () =>
    {
        try
        {
            using var peer = await accept;
            using var ssl = new SslStream(peer.GetStream(), false);
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(HandshakeLimitMs));
            await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = certificate,
                ClientCertificateRequired = false,
                EnabledSslProtocols = server,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            }, cts.Token);
            return $"server {ssl.SslProtocol}/{ssl.NegotiatedCipherSuite}";
        }
        catch (Exception ex) { return $"server {Describe(ex)}"; }
    });

    string client;
    using (var tcp = new TcpClient())
    {
        await tcp.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
        using var cssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(HandshakeLimitMs));
        try
        {
            await cssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "probe.example",
                EnabledSslProtocols = clientAllowed,
            }, cts.Token);
            client = $"client {cssl.SslProtocol}/{cssl.NegotiatedCipherSuite}";
        }
        catch (Exception ex) { client = $"client {Describe(ex)}"; }
    }

    var finished = await Task.WhenAny(serverLeg, Task.Delay(TimeSpan.FromMilliseconds(HandshakeLimitMs + 2000)));
    return $"{client} | {(finished == serverLeg ? await serverLeg : "server still waiting")}";
}

// ---- assert ----

static async Task<int> AssertAsync()
{
    Console.WriteLine($"== assert == {Header()}");
    var failures = new List<string>();
    using var fixture = BuildFixture();

    // The proxy sets these four on its SChannel legs, so a stack that turns one down is a stack the
    // proxy cannot run on. Checked as knobs, not as outcomes: the peer here is a stall.
    foreach (var (label, set) in new (string, Action<SslClientAuthenticationOptions>)[]
    {
        ("client EnabledSslProtocols 1.2|1.3", o => o.EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13),
        ("client TargetHost", o => o.TargetHost = "probe.example"),
        ("client ApplicationProtocols h2", o => o.ApplicationProtocols = [SslApplicationProtocol.Http2]),
        ("client validation callback", o => o.RemoteCertificateValidationCallback = (_, _, _, _) => true),
    })
    {
        var outcome = await TryClientAsync(set);
        Expect(failures, label, outcome, "accepted");
    }

    foreach (var (label, set) in new (string, Func<SslServerAuthenticationOptions, SslServerAuthenticationOptions>)[]
    {
        ("server leg as the proxy builds it", o => o),
        ("server EnabledSslProtocols 1.2|1.3", o => { o.EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13; return o; }),
    })
    {
        var outcome = await TryServerAsync(fixture, set);
        Expect(failures, label, outcome, "accepted");
    }

    // Which of 1.2 and 1.3 a pair lands on is the host's answer: a stack with no 1.3 terminates at 1.2, one
    // that has it at 1.3. What the proxy depends on is that each leg names a version it terminates at, and
    // that 1.2 alone still terminates - an upstream that stops at 1.2 has to be reachable from a leg that
    // offers nothing else.
    ExpectVersion(failures, "negotiate 1.2|1.3",
        await NegotiateAsync(SslProtocols.Tls12 | SslProtocols.Tls13, fixture.Leaf), "Tls12", "Tls13");
    ExpectVersion(failures, "negotiate 1.2",
        await NegotiateAsync(SslProtocols.Tls12, fixture.Leaf), "Tls12");

    if (failures.Count > 0)
    {
        Console.WriteLine($"\nassert: {failures.Count} FAILED");
        failures.ForEach(f => Console.WriteLine($"  {f}"));
        return 1;
    }
    Console.WriteLine("\nassert: ok");
    return 0;
}

static void Expect(List<string> failures, string label, string outcome, string needle)
{
    if (outcome.Contains(needle, StringComparison.Ordinal)) Console.WriteLine($"ok   {label}: {outcome}");
    else failures.Add($"{label}: expected to contain \"{needle}\", got {outcome}");
}

static void ExpectVersion(List<string> failures, string label, string outcome, params string[] allowed)
{
    var legs = outcome.Split(" | ", 2, StringSplitOptions.None);
    var names = new[] { "client", "server" };
    string? reason = legs.Length != 2 ? "the row does not hold two legs" : null;
    for (var i = 0; reason is null && i < legs.Length; i++)
    {
        var version = VersionOf(legs[i]);
        reason = version is null ? $"{names[i]} leg reported no version"
            : Array.IndexOf(allowed, version) < 0 ? $"{names[i]} {version} is not one of {string.Join('|', allowed)}"
            : null;
    }
    if (reason is null) Console.WriteLine($"ok   {label}: {outcome}");
    else failures.Add($"{label}: {reason}, got {outcome}");
}

/// <summary>The version token of a "client Tls12/TLS_..." half; null when the half reports a failure or a wait.</summary>
static string? VersionOf(string leg)
{
    var start = leg.IndexOf(' ');
    if (start < 0) return null;
    var end = leg.IndexOf('/', start);
    return end < 0 ? null : leg[(start + 1)..end];
}

// ---- fixture ----

static Fixture BuildFixture() => new();

static string Describe(Exception ex)
{
    var text = $"{ex.GetType().Name}: {FirstLine(ex.Message)}";
    for (var inner = ex.InnerException; inner is not null; inner = inner.InnerException)
        text += $" <- {inner.GetType().Name}: {FirstLine(inner.Message)}";
    return text;
}

static string FirstLine(string s) => s.Split('\n')[0].Trim();
