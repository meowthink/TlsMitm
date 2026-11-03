// Drives the real MitmProxy through a fake redirector: no WinDivert, no admin. The fake upstream
// speaks a real STARTTLS exchange, so the test covers protocol detection, the plaintext pumps,
// the readiness-reply decision and the SslStream handover on the same sockets.
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using TlsMitm;


// Several modes per process: each run gets its own listener, cert engine, redirector and proxy, so
// one mode cannot see another's state, while the root-store read, the CRL build and the engine setup
// are paid once per group instead of once per mode (measured at ~0.6s of every run).
var failed = new List<string>();
foreach (var mode in args.Length > 0 ? args : new[] { "smtp" })
    if (await RunModeAsync(mode) != 0) failed.Add(mode);
foreach (var m in failed) Console.WriteLine($"[Probe] FAIL {m}");
return failed.Count == 0 ? 0 : 1;

async Task<int> RunModeAsync(string mode)
{
    var notes = new List<string>();
    var failures = new List<string>();

    // A "live-ftps" mode points the proxy's upstream leg at a real server instead of the fake one. The
    // control leg still runs through the proxy, so everything the product does to a session - implicit
    // TLS detection, the leaf, the two pumps - stays under test; only the redirector is taken out.
    // Which server, and which file to ask for, comes from the environment: the mode needs an account on
    // the host, so the person running it names one they have, and curl reads it from .netrc.
    var liveHost = mode == "live-ftps" ? Environment.GetEnvironmentVariable("TLSMITM_LIVE_FTPS_HOST") : null;
    var livePort = int.Parse(Environment.GetEnvironmentVariable("TLSMITM_LIVE_FTPS_PORT") ?? "990");
    var livePath = Environment.GetEnvironmentVariable("TLSMITM_LIVE_FTPS_PATH") ?? "/";
    var isLive = liveHost != null;
    if (mode == "live-ftps" && liveHost == null)
    {
        Console.WriteLine("[Probe] live-ftps: SKIPPED, set TLSMITM_LIVE_FTPS_HOST to a FTPS server you can log into");
        return 0;
    }

    // The real-client media mode needs a media client, and this repo carries none: the person running it
    // names their own ffmpeg, the one binary here that speaks rtmps://.
    var ffmpegPath = mode == "rtmps-ffmpeg" ? Environment.GetEnvironmentVariable("TLSMITM_FFMPEG") : null;
    if (mode == "rtmps-ffmpeg" && (ffmpegPath == null || !File.Exists(ffmpegPath)))
    {
        Console.WriteLine($"[Probe] {mode}: SKIPPED, set TLSMITM_FFMPEG to an ffmpeg binary that speaks TLS");
        return 0;
    }

    Console.WriteLine($"[Probe] mode={mode}");

    using var upstreamKey = RSA.Create(2048);
    var upstreamReq = new CertificateRequest("CN=probe-upstream", upstreamKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    var upstreamCert = X509CertificateLoader.LoadPkcs12(
        upstreamReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1))
            .Export(X509ContentType.Pfx, ""),
        "", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

    // The 0-RTT mode needs one byte-exact expectation shared by both ends: the client sends this flight and
    // the fake upstream asserts it received precisely these bytes.
    var earlyDataFlight = BuildEarlyDataFlight();

    // IPv6 mode is the implicit-TLS exchange with every socket on ::1: the proxy has to accept a v6
    // peer, dial a v6 upstream through an exempted socket, and write a v6 capture for the run to pass.
    var loopbackIp = mode == "ipv6" ? IPAddress.IPv6Loopback : IPAddress.Loopback;
    var listener = new TcpListener(loopbackIp, 0);
    listener.Start();
    var upstreamPort = ((IPEndPoint)listener.LocalEndpoint).Port;
    var capturesBefore = Directory.Exists("captures") ? Directory.GetFiles("captures") : Array.Empty<string>();

    // The passive-mode modes need a second, late-bound destination: the data port only exists once the
    // fake server has opened it, and it is the second proxied connection that asks for it.
    var dataTarget = new TaskCompletionSource<IPEndPoint>(TaskCreationOptions.RunContinuationsAsynchronously);

    // Active mode binds the two halves the other way round: the client owns the port, and the server only
    // learns the substitute through the control channel. Both halves run at once, so the server reports
    // through its own lists.
    var clientListenPort = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
    var serverNotes = new List<string>();
    var serverFailures = new List<string>();

    // The ECH modes judge the handshake by what the upstream socket actually receives instead of by a
    // protocol exchange, so the fake upstream reports through this rather than speaking a dialect. The
    // length travels with the verdict: "no ECH here" is only evidence if some flight arrived at all.
    var echSeen = new TaskCompletionSource<(int Bytes, bool Ech)>(TaskCreationOptions.RunContinuationsAsynchronously);

    // The media dialects are judged at the far end of the session: what server name the proxy offered the
    // upstream when it dialled, and which octets of the dialect arrived after TLS was terminated. The name
    // is the whole question for a client that sends no server_name, because the leaf the client was served
    // is named from the destination address instead.
    var mediaSeen = new TaskCompletionSource<(string? Offered, byte[] First, byte[] Second)>(
        TaskCreationOptions.RunContinuationsAsynchronously);

    // The scripted media modes judge the same two questions, but after a whole dialogue instead of after one
    // flight: which name the proxy offered upstream, and how many turns the far end read back.
    var dialogueDone = new TaskCompletionSource<(string? Offered, string Protocol, int Turns)>(
        TaskCreationOptions.RunContinuationsAsynchronously);

    var serverTask = Task.Run(async () =>
    {
        if (isLive) return;
        // Auto serves a Node/Electron client followed by the probe itself (Windows store), which must
        // receive different chains. The first leg is optional because current clients may reject the
        // legacy eMSign root before completing the handshake.
        var acceptCount = mode == "auto" ? 2
            : mode == "mtls-refused" ? 2
            : mode is "grease" or "rootcheck" or "handshake-abort" or "filter" or "early-refuse" ? 0 : 1;
        for (var i = 0; i < acceptCount; i++)
        {
        using var accepted = await listener.AcceptTcpClientAsync();
        var stream = accepted.GetStream();
        switch (mode)
        {
            case "smtp": await ServeSmtpAsync(stream, upstreamCert); break;
            case "imap": await ServeImapAsync(stream, upstreamCert); break;
            case "pop3": await ServePop3Async(stream, upstreamCert); break;
            case "ftp": await ServeFtpAsync(stream, upstreamCert); break;
            case "nntp": await ServeNntpAsync(stream, upstreamCert); break;
            case "xmpp":
            case "xmpp-nosni": await ServeXmppAsync(stream, upstreamCert, split: false); break;
            case "xmpp-split": await ServeXmppAsync(stream, upstreamCert, split: true); break;
            case "xmpp-decline": await ServeXmppDeclineAsync(stream); break;
            case "xmpp-bad": await ServeXmppBadAsync(stream); break;
            case "ldap": await ServeLdapAsync(stream, upstreamCert); break;
            case "ldap-decline": await ServeLdapDeclineAsync(stream); break;
            case "ldap-bad": await ServeLdapBadAsync(stream); break;
            case "sunrpc":
                await ServeSunRpcAsync(stream, upstreamCert, serverNotes, serverFailures, split: false,
                    Rpc.Success); break;
            case "sunrpc-split":
                await ServeSunRpcAsync(stream, upstreamCert, serverNotes, serverFailures, split: true,
                    Rpc.Success); break;
            case "sunrpc-unavail":
                await ServeSunRpcAsync(stream, upstreamCert, serverNotes, serverFailures, split: false,
                    Rpc.ProgUnavail); break;
            case "sunrpc-decline": await ServeSunRpcDeclineAsync(stream); break;
            case "sunrpc-misuse": await ServeSunRpcMisuseAsync(stream, upstreamCert, serverNotes, serverFailures); break;
            case "sunrpc-near": await ServeSunRpcNearAsync(stream, upstreamCert, serverNotes, serverFailures); break;
            case "sunrpc-bad": await ServeSunRpcBadAsync(stream); break;
            case "sunrpc-wrong-token": await ServeSunRpcWrongTokenAsync(stream); break;
            case "sunrpc-wrong-flavor": await ServeSunRpcWrongFlavorAsync(stream); break;
            case "ftps-pasv": await ServeFtpDataAsync(stream, upstreamCert, dataTarget, false); break;
            case "ftps-epsv": await ServeFtpDataAsync(stream, upstreamCert, dataTarget, true); break;
            case "ftps-active":
            case "ftps-active-split":
            case "ftps-active-clear": await ServeFtpActiveAsync(stream, upstreamCert, serverNotes, serverFailures, clientListenPort, mode == "ftps-active-clear"); break;
            case "reject": await ServeRejectAsync(stream); break;
            case "ech-relay":
            case "ech-downgrade": await ServeEchUpstreamAsync(accepted, upstreamCert, echSeen); break;
            case "early-data": await ServeEarlyDataAsync(stream, earlyDataFlight, serverNotes, serverFailures); break;
            case "plain": await ServeEchoAsync(stream); break;
            case "grease": await ServeEchoAsync(stream); break;
            case "implicit":
            case "implicit-ip":
            case "ipv6":
            // alpn-fallback: the upstream selects no ALPN, which is what a measured search edge does.
            case "alpn-fallback": await ServeImplicitAsync(stream, upstreamCert); break;
            case "emsign": await ServeOptionalImplicitAsync(stream, upstreamCert); break;
            case "auto":
                if (i == 0) await ServeOptionalImplicitAsync(stream, upstreamCert);
                else await ServeImplicitAsync(stream, upstreamCert);
                break;
            case "alpn-h2": await ServeImplicitH2Async(stream, upstreamCert); break;
            case "rtsps": await ServeScriptedAsync(accepted, upstreamCert, Media.RtspScript(), "rtsps",
                serverNotes, serverFailures); break;
            case "rtmps": await ServeScriptedAsync(accepted, upstreamCert, Media.RtmpScript(), "rtmps",
                serverNotes, serverFailures); break;
            case "sips": await ServeScriptedAsync(accepted, upstreamCert, Media.SipScript(), "sips",
                serverNotes, serverFailures); break;
            case "rtmps-ffmpeg": await ServeMediaClientUpstreamAsync(accepted, upstreamCert, mediaSeen,
                serverNotes, serverFailures); break;
            case "smtpsplit": await ServeSmtpSplitAsync(stream, upstreamCert); break;
            case "https-close": await ServeHttpsCloseAsync(stream, upstreamCert, serverNotes); break;
            // The first connection refuses the hello the proxy composed; the second is a normal
            // server, which is where the client's own hello has to arrive instead.
            case "mtls-refused":
                if (i == 0) await ServeRefuseHandshakeAsync(stream, serverNotes);
                else await ServeImplicitAsync(stream, upstreamCert);
                break;
            default: throw new ArgumentException($"unknown mode '{mode}'");
        }
        }
    });

    // A strict client such as curl/Schannel checks revocation before it looks at anything else, so the
    // harness has to serve the same CRL the product does or every curl-based probe dies at the handshake.
    var rootForClient = LoadRootForProbe();
    using var crlService = CrlService.Start(rootForClient);
    // emSign mode is the one that proves the libssl client leg: the leaf must be issued by a CA that
    // Node/Electron trust natively, and only a client outside the Windows trust store can judge that.
    var emSignCas = mode is "emsign" or "auto" or "handshake-abort" ? LoadEmSignCas() : new List<EmSignCa>();
    var certEngine = new CertEngine(rootForClient, emSignCas,
        mode == "auto" ? CertEngineMode.Auto
            : emSignCas.Count > 0 ? CertEngineMode.EmSignOnly : CertEngineMode.FiddlerOnly, crlService);

    IPEndPoint? liveTarget = null;
    string? rootPemPath = null;
    if (isLive)
    {
        liveTarget = new IPEndPoint(Dns.GetHostAddresses(liveHost!).First(a => a.AddressFamily == AddressFamily.InterNetwork), livePort);
        rootPemPath = Path.Combine(Path.GetTempPath(), "probe-root.pem");
        File.WriteAllText(rootPemPath,
            $"-----BEGIN CERTIFICATE-----\n{Convert.ToBase64String(rootForClient.RawData, Base64FormattingOptions.InsertLineBreaks)}\n-----END CERTIFICATE-----\n");
        Console.WriteLine($"[Probe] live upstream {liveHost}:{livePort} = {liveTarget}, root pem {rootPemPath}");
    }

    // The second and later connections are the FTP data channel. Nothing in this harness can name that
    // endpoint in advance, and live it is rewritten by the redirector instead, so send the upstream
    // connect somewhere closed rather than blocking a thread waiting for a target that never arrives.
    var redirector = new FakeRedirector(index => index == 0 || mode == "auto"
        ? liveTarget ?? new IPEndPoint(loopbackIp, upstreamPort)
        : liveTarget != null
            ? new IPEndPoint(IPAddress.Loopback, 1)
            : dataTarget.Task.GetAwaiter().GetResult());
    var proxyPort = FreePort();
    // Only the terminate mode is given an ECH state machine; with none, the proxy relays the hello blind,
    // which is the other half of the pair.
    var proxy = new MitmProxy(certEngine, redirector, proxyPort,
        mode == "ech-downgrade" ? new EchDowngrade() : null);
    using var cts = new CancellationTokenSource();
    _ = proxy.StartAsync(cts.Token);

    try
    {
        if (mode is "emsign" or "auto")
        {
            // The judge has to be a client that trusts emSign and rejects the Fiddler root, which rules
            // out Schannel. Electron is preferred when installed; otherwise Node supplies the same
            // bundled TLS stack on a clean runner.
            await RunEmsignClientAsync(proxyPort, notes, failures).WaitAsync(TimeSpan.FromSeconds(90));

            if (mode == "auto")
            {
                // The other half of the decision: the probe itself is an ordinary Windows-store client,
                // so the same engine must hand it a Fiddler-chained leaf and the relay must still work.
                using var tcp = new TcpClient();
                await tcp.ConnectAsync(loopbackIp, proxyPort);
                await ClientFiddlerAsync(tcp.GetStream(), "probe.test", notes)
                    .WaitAsync(TimeSpan.FromSeconds(20));
            }
        }
        else if (mode == "handshake-abort")
        {
            // A client that refuses the flight is the one session no relay pcap covers - it ends before
            // "MITM established" - so the handshake capture has to be what makes a rejection diagnosable.
            // The client here is a Node/Electron one pointed at a CA list that cannot contain our anchor,
            // which makes the refusal a property of the fixture rather than of this machine's stores.
            var foreignCaPem = Path.Combine(Path.GetTempPath(), $"probe-foreign-ca-{Environment.ProcessId}.pem");
            File.WriteAllText(foreignCaPem,
                $"-----BEGIN CERTIFICATE-----\n{Convert.ToBase64String(upstreamCert.RawData, Base64FormattingOptions.InsertLineBreaks)}\n-----END CERTIFICATE-----\n");
            await RunAbortClientAsync(proxyPort, foreignCaPem, notes, failures)
                .WaitAsync(TimeSpan.FromSeconds(30));
            await CheckAbortedCaptureAsync(capturesBefore, upstreamPort, notes, failures);
        }
        else if (mode == "grease")
        {
            // Parsing only: the decision is made before any socket exists, so no traffic is needed.
            await CheckGreaseAsync(notes, failures);
        }
        else if (mode == "rootcheck")
        {
            CheckRootSelection(rootForClient, notes, failures);
            CheckGeneratedRoot(notes, failures);
        }
        else if (mode == "filter")
        {
            // Scoping is decided in the redirector before any socket exists, so it is judged here
            // without traffic: only the decision table needs to be right, not a handshake.
            CheckProcessFilter(notes, failures);
        }
        else if (mode == "early-refuse")
        {
            // Not the proxy: this measures the terminator the proxy hands a session to, because the
            // question is whether that stack can be given a hello offering early data at all.
            await CheckEarlyRefuseAsync(upstreamCert, notes, failures);
        }
        else if (mode is "ech-relay" or "ech-downgrade")
        {
            // The client here is not a handshake, it is one hand-built record: whether the ECH extension
            // reaches the upstream or is replaced there is the whole question, and only a writer outside
            // SslStream can put 0xFE0D on the wire verbatim.
            await RunEchClientAsync(proxyPort, loopbackIp, echSeen, mode == "ech-downgrade", notes, failures)
                .WaitAsync(TimeSpan.FromSeconds(20));
        }
        else if (mode == "https-close")
        {
            // .NET's SslStream accepts a bare FIN where a close_notify was promised; Schannel does not,
            // and Schannel is the client that failed live. curl is the strict judge here.
            await RunCurlAsync(proxyPort, notes, failures).WaitAsync(TimeSpan.FromSeconds(30));
        }
        else if (mode == "rtmps-ffmpeg")
        {
            // A third party's TLS stack, not this harness's: whether the product terminates a real
            // rtmps:// session is judged from what the fake upstream ends up holding.
            await RunFfmpegMediaClientAsync(mode, proxyPort, ffmpegPath!, mediaSeen, notes, failures)
                .WaitAsync(TimeSpan.FromSeconds(60));
        }
        else if (isLive)
        {
            await RunLiveFtpsAsync(proxyPort, rootPemPath!, liveHost!, livePort, livePath, notes, failures)
                .WaitAsync(TimeSpan.FromSeconds(90));
        }
        else
        {
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(loopbackIp, proxyPort);
            // A media mode runs a scripted dialogue, where every turn of the dialect is a round trip of its
            // own and the RTMP handshake alone moves 4.5 KB; the one-exchange modes keep the shorter clock.
            var budget = mode is "rtsps" or "rtmps" or "sips"
                ? TimeSpan.FromSeconds(60) : TimeSpan.FromSeconds(20);
            await RunClientAsync(mode, tcp.GetStream(), notes).WaitAsync(budget);
        }

        // A relay that completes proves the sockets span v6; only the file proves the capture does.
        if (mode == "ipv6")
            await CheckIpv6CaptureAsync(capturesBefore, notes, failures);
    }
    catch (Exception ex)
    {
        failures.Add($"client: {ex.GetType().Name}: {ex.Message}");
    }

    cts.Cancel();
    try
    {
        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));
    }
    catch (Exception ex)
    {
        failures.Add($"server: {ex.GetType().Name}: {ex.Message}");
    }

    // The proxy gives back the flow it claimed by its token when its own session ends. The release runs
    // on the session's task, not the client's, so wait for it rather than judge a race. A mode that
    // never opens a session - grease, rootcheck, filter - claims nothing and is judged on nothing.
    var releaseDeadline = DateTime.UtcNow.AddSeconds(3);
    while (redirector.Releases < redirector.Claims && DateTime.UtcNow < releaseDeadline)
        await Task.Delay(20);
    if (redirector.Releases != redirector.Claims)
        failures.Add($"flow tokens: {redirector.Releases} released of {redirector.Claims} claimed");

    foreach (var note in notes) Console.WriteLine($"  {note}");
    foreach (var note in serverNotes) Console.WriteLine($"  {note}");
    failures.AddRange(serverFailures);
    foreach (var failure in failures) Console.WriteLine($"  FAIL {failure}");
    Console.WriteLine(failures.Count == 0 ? "[Probe] PASS" : "[Probe] FAIL");
    return failures.Count == 0 ? 0 : 1;

    async Task RunClientAsync(string mode, NetworkStream s, List<string> notes)
    {
        switch (mode)
        {
            case "smtp": await ClientSmtpAsync(s, notes); break;
            case "imap": await ClientImapAsync(s, notes); break;
            case "pop3": await ClientPop3Async(s, notes); break;
            case "ftp": await ClientFtpAsync(s, notes); break;
            case "nntp": await ClientNntpAsync(s, notes); break;
            case "xmpp": await ClientXmppAsync(s, notes, split: false); break;
            case "xmpp-nosni": await ClientXmppNoSniAsync(s, notes, failures); break;
            case "xmpp-split": await ClientXmppAsync(s, notes, split: true); break;
            case "xmpp-decline": await ClientXmppDeclineAsync(s, notes); break;
            case "xmpp-bad": await ClientXmppBadAsync(s, notes); break;
            case "ldap": await ClientLdapAsync(s, notes, failures); break;
            case "ldap-decline": await ClientLdapDeclineAsync(s, notes); break;
            case "ldap-bad": await ClientLdapBadAsync(s, notes); break;
            case "sunrpc": await ClientSunRpcAsync(s, notes, failures, split: false, Rpc.Success); break;
            case "sunrpc-split": await ClientSunRpcAsync(s, notes, failures, split: true, Rpc.Success); break;
            case "sunrpc-unavail": await ClientSunRpcAsync(s, notes, failures, split: false, Rpc.ProgUnavail); break;
            case "sunrpc-decline": await ClientSunRpcDeclineAsync(s, notes); break;
            case "sunrpc-misuse": await ClientSunRpcMisuseAsync(s, notes, failures); break;
            case "sunrpc-near": await ClientSunRpcNearAsync(s, notes, failures); break;
            case "sunrpc-bad": await ClientSunRpcBadAsync(s, notes); break;
            case "sunrpc-wrong-token": await ClientSunRpcWrongTokenAsync(s, notes); break;
            case "sunrpc-wrong-flavor": await ClientSunRpcWrongFlavorAsync(s, notes); break;
            case "ftps-pasv": await ClientFtpDataAsync(s, notes, failures, proxyPort, false); break;
            case "ftps-epsv": await ClientFtpDataAsync(s, notes, failures, proxyPort, true); break;
            case "ftps-active":
            case "ftps-active-split":
            case "ftps-active-clear": await ClientFtpActiveAsync(s, notes, failures, clientListenPort,
                mode == "ftps-active-split", mode == "ftps-active-clear"); break;
            case "reject": await ClientRejectAsync(s); break;
            case "early-data": await ClientEarlyDataAsync(s, earlyDataFlight, notes, failures); break;
            case "plain": await ClientPlainAsync(s); break;
            case "implicit": await ClientImplicitAsync(s, "probe.test", notes); break;
            case "implicit-ip": await ClientImplicitAsync(s, "127.0.0.1", notes); break;
            case "ipv6": await ClientImplicitAsync(s, "probe.test", notes); break;
            case "alpn-fallback": await ClientAlpnAsync(s, "probe.test", notes); break;
            case "rtsps":
                await CheckSniVisibilityAsync(upstreamCert, notes, failures);
                await ClientScriptedAsync(s, Media.RtspScript(), "rtsps", notes, failures);
                break;
            case "rtmps": await ClientScriptedAsync(s, Media.RtmpScript(), "rtmps", notes, failures); break;
            case "sips": await ClientScriptedAsync(s, Media.SipScript(), "sips", notes, failures); break;
            case "alpn-h2": await ClientAlpnH2Async(s, "probe.test", notes); break;
            case "smtpsplit": await ClientSmtpSplitAsync(s, notes); break;
            case "mtls-refused": await ClientAfterRefusalAsync(s, "probe.test", notes, failures); break;
            default: throw new ArgumentException($"unknown mode '{mode}'");
        }
    }

    static async Task ClientSmtpAsync(NetworkStream s, List<string> notes)
    {
        await ExpectAsync(s, "220");
        await SendAsync(s, "EHLO probe\r\n");
        await ExpectMultilineAsync(s, "250");

        await SendAsync(s, "MAIL FROM:<a@b>\r\n");
        await ExpectAsync(s, "250");
        await SendAsync(s, "RCPT TO:<c@d>\r\n");
        await ExpectAsync(s, "250");
        await SendAsync(s, "DATA\r\n");
        await ExpectAsync(s, "354");

        // A body line shaped exactly like the STARTTLS command must be relayed as data, not acted on.
        await SendAsync(s, "subject\r\nSTARTTLS\r\n250 OK\r\n.\r\n");
        await ExpectAsync(s, "250");

        await SendAsync(s, "STARTTLS\r\n");
        await ExpectAsync(s, "220");

        var ssl = await UpgradeAsync(s, "probe.test", notes);
        await SendAsync(ssl, "HELLO\r\n");
        await ExpectAsync(ssl, "250");
        notes.Add("smtp: DATA body containing STARTTLS was relayed, the real STARTTLS upgraded");
    }

    static async Task ClientImapAsync(NetworkStream s, List<string> notes)
    {
        await ExpectAsync(s, "* OK");
        await SendAsync(s, "a1 CAPABILITY\r\n");
        await ExpectAsync(s, "* CAPABILITY");
        await ExpectAsync(s, "a1 OK");
        await SendAsync(s, "a2 STARTTLS\r\n");
        await ExpectAsync(s, "a2 OK");

        var ssl = await UpgradeAsync(s, "probe.test", notes);
        await SendAsync(ssl, "a3 NOOP\r\n");
        await ExpectAsync(ssl, "a3 OK");
        notes.Add("imap: tagged STARTTLS upgraded");
    }

    static async Task ClientPop3Async(NetworkStream s, List<string> notes)
    {
        await ExpectAsync(s, "+OK");
        await SendAsync(s, "STLS\r\n");
        await ExpectAsync(s, "+OK");

        var ssl = await UpgradeAsync(s, "probe.test", notes);
        await SendAsync(ssl, "CAPA\r\n");
        await ExpectAsync(ssl, "+OK");
        notes.Add("pop3: STLS upgraded");
    }

    static async Task ClientFtpAsync(NetworkStream s, List<string> notes)
    {
        await ExpectAsync(s, "220");
        await SendAsync(s, "AUTH TLS\r\n");
        await ExpectAsync(s, "234");

        var ssl = await UpgradeAsync(s, "probe.test", notes);
        await SendAsync(ssl, "PBSZ 0\r\n");
        await ExpectAsync(ssl, "200");
        notes.Add("ftp: AUTH TLS upgraded");
    }

    static async Task ClientNntpAsync(NetworkStream s, List<string> notes)
    {
        await ExpectAsync(s, "200");
        await SendAsync(s, "STARTTLS\r\n");
        await ExpectAsync(s, "382");

        var ssl = await UpgradeAsync(s, "probe.test", notes);
        await SendAsync(ssl, "CAPABILITY\r\n");
        await ExpectAsync(ssl, "101");
        notes.Add("nntp: 382 upgraded in place");
    }

    // LDAP's StartTLS is an extended operation, not a line (RFC 4511 §4.14). A whoami operation
    // (RFC 4532 §2) runs first, and its response is also a success ExtendedResponse, so only the
    // messageID the response carries can pick out the grant (RFC 4511 §4.1.1.1).
    static async Task ClientLdapAsync(NetworkStream s, List<string> notes, List<string> failures)
    {
        await SendBytesAsync(s, WhoamiRequest(1));
        await ExpectBytesAsync(s, WhoamiResponse(1), "whoami response");

        await SendStartTlsRequestAsync(s, 2);
        await ExpectBytesAsync(s, StartTlsResponse(2, 0, null), "StartTLS response");

        var ssl = await UpgradeAsync(s, "probe.test", notes);
        await SendBytesAsync(ssl, WhoamiRequest(3));
        var content = await ExpectBytesAsync(ssl, WhoamiResponse(3), "post-TLS whoami response");
        if (!Encoding.ASCII.GetString(content).Contains("u:probe@example.net"))
            failures.Add("ldap: the post-TLS whoami response lost its authzId");
        notes.Add("ldap: a success ExtendedResponse for another operation was relayed, the StartTLS grant upgraded");
    }

    // The refusal half: RFC 4511 §4.14.2 leaves the session without a TLS layer when the resultCode is
    // not success, and names unavailable (52, §4.1.9) as the code for a TLS subsystem that is not there.
    static async Task ClientLdapDeclineAsync(NetworkStream s, List<string> notes)
    {
        await SendBytesAsync(s, WhoamiRequest(1));
        await ExpectBytesAsync(s, WhoamiResponse(1), "whoami response");

        await SendStartTlsRequestAsync(s, 2);
        await ExpectBytesAsync(s, StartTlsResponse(2, 52, "TLS subsystem unavailable"), "refusal");

        await SendBytesAsync(s, WhoamiRequest(3));
        await ExpectBytesAsync(s, WhoamiResponse(3), "plaintext whoami response");
        notes.Add("ldap-decline: unavailable(52) was relayed and the session carried on in plaintext");
    }

    // The gate LDAP detection hangs on is the client's first octet, so a stream that opens with a
    // SEQUENCE tag and is not BER has to survive as an untouched relay. 0x30 0x80 is the indefinite
    // length form RFC 4511 §5.1 rules out, which ends the walk after two octets.
    static async Task ClientLdapBadAsync(NetworkStream s, List<string> notes)
    {
        await SendBytesAsync(s, [0x30, 0x80]);
        await Task.Delay(150);
        await SendAsync(s, "PING\r\n");
        await ExpectAsync(s, "PONG");
        notes.Add("ldap-bad: an indefinite-length envelope was relayed as opaque octets");
    }

    // The shape wldap32 sends, measured here as 39 octets: both outer lengths in the four-octet long
    // form, and the requestName as the dotted text of an LDAPOID (RFC 4511 §4.1.2) rather than the
    // DER of the identifier. Written in three pieces so the walk has to reassemble the long form, the
    // messageID and the OID across chunk boundaries.
    static async Task SendStartTlsRequestAsync(Stream s, long messageId)
    {
        var request = StartTlsRequest(messageId);
        await SendBytesAsync(s, request[..3]);
        await Task.Delay(150);
        await SendBytesAsync(s, request[3..20]);
        await Task.Delay(150);
        await SendBytesAsync(s, request[20..]);
    }

    // The RPC-with-TLS grant half (RFC 9289 §4.1). A NULL call with no credential goes first and is answered
    // like any other call, so the only octet set that can end the plaintext session is the probe's AUTH_TLS
    // flavor. `split` sends both the first call and the probe as one record of three fragments arriving in
    // separate writes - one of them empty, which §11 allows, and for the probe the last of them cut in two -
    // which is what the record walk has to reassemble. `grantStat` is the accept_stat of the grant, and §4.1 has
    // the client start TLS whatever that says.
    static async Task ClientSunRpcAsync(NetworkStream s, List<string> notes, List<string> failures,
        bool split, uint grantStat)
    {
        if (split)
        {
            // One record in three fragments written separately, so each boundary falls between reads rather
            // than inside one (§11 lets a record carry any number of fragments, and a fragment of no octets).
            foreach (var fragment in Rpc.CallFragments(0x1111))
            {
                await SendBytesAsync(s, fragment);
                await Task.Delay(150);
            }
        }
        else
        {
            await SendBytesAsync(s, Rpc.NullCall(0x1111));
        }
        await ExpectBytesAsync(s, Rpc.AcceptedReply(0x1111), "reply to the first call");

        // The probe's own record spread over fragments, the middle of them empty and the last of them cut by a
        // write boundary: §11 makes a record "one or more record fragments" of "0 to (2**31) - 1 bytes" each, so
        // the forty octets §4.1's probe is made of have to be reassembled from whatever the stream hands over.
        if (split)
        {
            foreach (var fragment in Rpc.ProbeFragments(0x2222))
            {
                await SendBytesAsync(s, fragment);
                await Task.Delay(150);
            }
        }
        else
        {
            await SendBytesAsync(s, Rpc.Probe(0x2222));
        }
        // Two records that cannot settle the probe arrive before the grant does. The first is the probe echoed
        // back: §9's rpc_msg union picks its arm by msgtype, so a CALL on the reply side is not an answer to
        // anything whatever its xid. The second carries the §4.1 token but the xid of a call that is not the
        // probe, and §9 has a REPLY answer the CALL it matches, so it is not the grant either.
        await ExpectBytesAsync(s, Rpc.Probe(0x2222), "the probe echoed back on the reply side");
        await ExpectBytesAsync(s, Rpc.Grant(0x9999, Rpc.Success), "a grant whose xid matches no call");
        await ExpectBytesAsync(s, Rpc.Grant(0x2222, grantStat), "grant");
        var tls = await ClientSunRpcTunnelAsync(s, notes, failures);
        notes.Add("sunrpc: a call with no credential was answered, the probe's own octets and a token-bearing " +
            "reply for another xid were both passed by, the grant that matched the probe was followed, and RPC " +
            $"records round-tripped inside the tunnel (TLS={tls})");
    }

    // The tunnel both this mode and `sunrpc-misuse` have to finish: §4.1 has the ClientHello arrive on this
    // same connection and §5 requires it to carry the §7.2 identifier, which the proxy has to copy into the
    // hello it composes for the upstream.
    static async Task<SslProtocols> ClientSunRpcTunnelAsync(Stream s, List<string> notes, List<string> failures)
    {
        var ssl = await UpgradeAsync(s, "probe.test", notes, offer: [Rpc.Alpn]);
        if (ssl.NegotiatedApplicationProtocol != Rpc.Alpn)
            failures.Add($"the client leg answered '{ssl.NegotiatedApplicationProtocol}' although the upstream " +
                $"selected '{Rpc.Alpn}'");

        await SendBytesAsync(ssl, Rpc.NullCall(0x3333));
        await ExpectBytesAsync(ssl, Rpc.AcceptedReply(0x3333), "post-TLS reply");
        return ssl.SslProtocol;
    }

    // RFC 9289 §4.1 makes an AUTH_TLS credential on any other procedure a misuse the server must refuse, and a
    // refusal is only about *that* probe: the client sends no ClientHello, then probes again as the section
    // prescribes and this time the grant stands. A scanner that read the refused record as the probe would
    // settle this session as refused and relay the granted one, so the client's hello would reach the upstream
    // and its self-signed leaf would be the only answer.
    static async Task ClientSunRpcMisuseAsync(NetworkStream s, List<string> notes, List<string> failures)
    {
        await SendBytesAsync(s, Rpc.AuthTlsCall(0x1111, 11));
        await ExpectBytesAsync(s, Rpc.Denial(0x1111), "refusal of the misuse");

        // The same 44 octets but for the procedure and the xid, so only §4.1's NULL-procedure test separates
        // this record from the one the server just refused.
        await SendBytesAsync(s, Rpc.Probe(0x2222));
        await ExpectBytesAsync(s, Rpc.Grant(0x2222, Rpc.Success), "grant after the refusal");
        await ClientSunRpcTunnelAsync(s, notes, failures);
        notes.Add("sunrpc-misuse: AUTH_TLS on proc 11 was refused, the probe on proc 0 that followed was " +
            "granted and the tunnel it opened carried RPC records");
    }

    // The near-miss half. Every one of these records has an AUTH_TLS credential on the NULL procedure, so what
    // stops it from being the probe is a single word. None of them may move this socket into TLS, and the walk
    // has to stay in step with the record boundaries after each, because the probe that follows them is what
    // opens the tunnel.
    static async Task ClientSunRpcNearAsync(NetworkStream s, List<string> notes, List<string> failures)
    {
        foreach (var (xid, record) in Rpc.NearProbes())
        {
            await SendBytesAsync(s, record);
            await ExpectBytesAsync(s, Rpc.AcceptedReply(xid), $"reply to near-probe 0x{xid:X4}");
        }
        await SendBytesAsync(s, Rpc.Probe(0x2222));
        await ExpectBytesAsync(s, Rpc.Grant(0x2222, Rpc.Success), "grant after the near-probes");
        await ClientSunRpcTunnelAsync(s, notes, failures);
        notes.Add("sunrpc-near: six records that read like the AUTH_TLS probe were answered as the ordinary " +
            "calls they are, and the probe that followed still opened the tunnel");
    }

    // The refusal half. RFC 9289 §4.1 prescribes MSG_DENIED / AUTH_ERROR / AUTH_BADCRED for an AUTH_TLS
    // credential on any procedure other than the NULL procedure, and a server with no RPC-with-TLS answers the
    // probe as the credential it does not know. Neither grants anything, so after each the client sends no
    // ClientHello and the records either side exchanges next have to arrive whole.
    static async Task ClientSunRpcDeclineAsync(NetworkStream s, List<string> notes)
    {
        await SendBytesAsync(s, Rpc.AuthTlsCall(0x1111, 11));
        await ExpectBytesAsync(s, Rpc.Denial(0x1111), "refusal of the misuse");

        // 44 octets whose every field but the xid and the procedure matches the record just refused, so this
        // pair pins the NULL-procedure test rather than the flavor, the lengths or the program fields.
        await SendBytesAsync(s, Rpc.Probe(0x2222));
        await ExpectBytesAsync(s, Rpc.Denial(0x2222), "refusal of the probe");

        await SendBytesAsync(s, Rpc.NullCall(0x3333));
        await ExpectBytesAsync(s, Rpc.AcceptedReply(0x3333), "plaintext reply after the refusals");
        notes.Add("sunrpc-decline: AUTH_TLS on proc 11 and then on proc 0 were both refused and the session " +
            "carried on in plaintext");
    }

    // The shape of a MSG_ACCEPTED that is not a grant: the probe is answered, no ClientHello follows, and the
    // records either side exchanges next have to arrive whole. Each of the three modes below hands this helper
    // the one reply that fails exactly one clause of §4.1's grant predicate.
    static async Task ClientSunRpcNoGrantAsync(NetworkStream s, List<string> notes, byte[] answer,
        string label, string note)
    {
        await SendBytesAsync(s, Rpc.Probe(0x2222));
        await ExpectBytesAsync(s, answer, $"{label} answer to the probe");
        await SendBytesAsync(s, Rpc.NullCall(0x3333));
        await ExpectBytesAsync(s, Rpc.AcceptedReply(0x3333), $"plaintext reply after the {label} answer");
        notes.Add(note);
    }

    // A server that knows the program but not RPC-with-TLS answers the probe as the plain NULL call it is, with
    // an AUTH_NONE verifier of no octets at all.
    static Task ClientSunRpcBadAsync(NetworkStream s, List<string> notes) =>
        ClientSunRpcNoGrantAsync(s, notes, Rpc.AcceptedReply(0x2222), "no-token",
            "sunrpc-bad: a MSG_ACCEPTED whose verifier carries no octets was read as no grant and the session " +
            "carried on in plaintext");

    // The reply that is only wrong in its eight octets: MSG_ACCEPTED, AUTH_NONE, a verifier of exactly eight,
    // and none of them spelling "STARTTLS". §4.1's "does not contain the token" clause is the only thing that
    // keeps this from being a grant, so this mode is the only thing that holds the token comparison itself.
    static Task ClientSunRpcWrongTokenAsync(NetworkStream s, List<string> notes) =>
        ClientSunRpcNoGrantAsync(s, notes, Rpc.NotGrant(0x2222), "wrong-token",
            "sunrpc-wrong-token: an AUTH_NONE verifier of eight octets that do not spell STARTTLS was " +
            "read as no grant and the session carried on in plaintext");

    // The same eight octets spelled correctly and filed under the wrong flavor: §4.1 has "The flavor value of
    // the verifier in the RPC Reply message received from the server MUST be AUTH_NONE" before it speaks of the
    // token at all. This is the only mode that separates the verifier's flavor from its body, so a scanner that
    // looked only for the token would upgrade here.
    static Task ClientSunRpcWrongFlavorAsync(NetworkStream s, List<string> notes) =>
        ClientSunRpcNoGrantAsync(s, notes, Rpc.WrongFlavor(0x2222), "wrong-flavor",
            "sunrpc-wrong-flavor: an AUTH_SYS verifier spelling STARTTLS was read as no grant and the session " +
            "carried on in plaintext");

    static async Task ClientFtpDataAsync(NetworkStream s, List<string> notes, List<string> failures, int proxyPort, bool epsv)
    {
        await ExpectAsync(s, "220");
        await SendAsync(s, "AUTH TLS\r\n");
        await ExpectAsync(s, "234");

        var control = await UpgradeAsync(s, "probe.test", notes);
        await SendAsync(control, "PBSZ 0\r\n");
        await ExpectAsync(control, "200");
        await SendAsync(control, "PROT P\r\n");
        await ExpectAsync(control, "200");

        await SendAsync(control, epsv ? "EPSV\r\n" : "PASV\r\n");
        var reply = await ReadLineAsync(control);
        var dataPort = epsv ? ParseEpsvPort(reply) : ParsePasvPort(reply);
        notes.Add($"ftps: reply '{reply}' names data port {dataPort}");

        // The data channel is a fresh TLS session to an ephemeral port and, as most FTPS clients send
        // it, carries no server_name at all.
        using var dataTcp = new TcpClient();
        await dataTcp.ConnectAsync(IPAddress.Loopback, proxyPort);
        var data = await UpgradeWithoutSniAsync(dataTcp.GetStream(), notes);

        await SendAsync(control, "RETR report.txt\r\n");
        await ExpectAsync(control, "150");

        var payload = new byte[15];
        var got = 0;
        while (got < payload.Length)
        {
            var n = await data.ReadAsync(payload.AsMemory(got));
            if (n == 0) break;
            got += n;
        }
        if (Encoding.ASCII.GetString(payload, 0, got) != "hello over ftps")
            failures.Add($"data channel carried '{Encoding.ASCII.GetString(payload, 0, got)}'");

        var leaf = data.RemoteCertificate as X509Certificate2;
        var dns = string.Join(",", leaf is null ? Array.Empty<string>() : DnsNames(leaf));
        notes.Add($"ftps: data-channel leaf subject='{leaf?.Subject}' SAN dns=[{dns}]");
        if (!dns.Contains("probe.test"))
            failures.Add($"data channel was named '{dns}' instead of the control session's host");

        await ExpectAsync(control, "226");
        await SendAsync(control, "QUIT\r\n");
        await ExpectAsync(control, "221");
        notes.Add($"ftps({(epsv ? "epsv" : "pasv")}): data channel relayed the transfer");
    }

    // Active mode: the client listens and the server connects, yet the client is still the TLS client.
    // The proxy has to answer the server at a port of its own and carry the transfer to the client's.
    static async Task ClientFtpActiveAsync(NetworkStream s, List<string> notes, List<string> failures,
        TaskCompletionSource<int> listenPort, bool split, bool clear)
    {
        await ExpectAsync(s, "220");
        await SendAsync(s, "AUTH TLS\r\n");
        await ExpectAsync(s, "234");

        var control = await UpgradeAsync(s, "probe.test", notes);
        await SendAsync(control, "PBSZ 0\r\n");
        await ExpectAsync(control, "200");
        await SendAsync(control, clear ? "PROT C\r\n" : "PROT P\r\n");
        await ExpectAsync(control, "200");

        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var named = (IPEndPoint)listener.LocalEndpoint;
        listenPort.SetResult(named.Port);

        // PORT carries the address as six comma-separated octets, not as dotted text.
        var command = $"PORT {string.Join(',', named.Address.GetAddressBytes())},{named.Port >> 8},{named.Port & 0xFF}\r\n";
        if (split)
        {
            // Split inside the verb and again inside the arguments: the withheld line has to be
            // reassembled across two read boundaries before it can be substituted.
            await SendAsync(control, command[..2]);
            await Task.Delay(150);
            await SendAsync(control, command[2..13]);
            await Task.Delay(150);
            await SendAsync(control, command[13..]);
        }
        else
        {
            await SendAsync(control, command);
        }
        await ExpectAsync(control, "200");
        notes.Add($"ftps-active{(split ? "-split" : clear ? "-clear" : "")}: the client listens on {named.Port} and named it in PORT");

        await SendAsync(control, "RETR report.txt\r\n");
        await ExpectAsync(control, "150");

        using var dataTcp = await listener.AcceptTcpClientAsync().WaitAsync(TimeSpan.FromSeconds(15));
        // The client is the TLS client even though it is the peer being connected to. A PROT C transfer
        // is served by the upstream's own certificate, which this probe does not trust, so only the
        // intercepted run validates.
        var data = await UpgradeAsync(dataTcp.GetStream(), "probe.test", notes, acceptAny: clear);

        var payload = new byte[15];
        var got = 0;
        while (got < payload.Length)
        {
            var n = await data.ReadAsync(payload.AsMemory(got));
            if (n == 0) break;
            got += n;
        }
        if (Encoding.ASCII.GetString(payload, 0, got) != "hello over ftps")
            failures.Add($"active data channel carried '{Encoding.ASCII.GetString(payload, 0, got)}'");

        var leaf = data.RemoteCertificate as X509Certificate2;
        var dns = string.Join(",", leaf is null ? Array.Empty<string>() : DnsNames(leaf));
        notes.Add($"ftps-active: data-channel leaf subject='{leaf?.Subject}' SAN dns=[{dns}]");
        if (clear)
        {
            if (leaf?.Subject.Contains("probe-upstream") != true)
                failures.Add($"PROT C: the data channel was named '{leaf?.Subject}', so the proxy stepped in anyway");
        }
        else if (!dns.Contains("probe.test"))
            failures.Add($"active data channel was named '{dns}' instead of the control session's host");

        data.Dispose();
        await ExpectAsync(control, "226");
        await SendAsync(control, "QUIT\r\n");
        await ExpectAsync(control, "221");
        notes.Add(clear
            ? "ftps-active-clear: PROT C left the PORT and the transfer to the peers"
            : "ftps-active: the server's connect-back reached the client's own listening port");
    }

    static IPEndPoint ParsePortCommand(string line)
    {
        var octets = line.Substring(line.IndexOf(' ') + 1).Split(',');
        if (octets.Length != 6) throw new InvalidOperationException($"malformed PORT '{line}'");
        var address = IPAddress.Parse($"{octets[0]}.{octets[1]}.{octets[2]}.{octets[3]}");
        return new IPEndPoint(address, (int.Parse(octets[4]) << 8) | int.Parse(octets[5]));
    }

    static int ParsePasvPort(string line)
    {
        var open = line.IndexOf('(');
        var close = line.IndexOf(')', open);
        var octets = line[(open + 1)..close].Split(',');
        if (octets.Length != 6) throw new InvalidOperationException($"malformed 227 reply '{line}'");
        return (int.Parse(octets[4]) << 8) | int.Parse(octets[5]);
    }

    static int ParseEpsvPort(string line)
    {
        var start = line.IndexOf('|') + 3;
        var end = line.LastIndexOf('|');
        return int.Parse(line[start..end]);
    }

    static IEnumerable<string> DnsNames(X509Certificate2 cert)
    {
        foreach (var ext in cert.Extensions)
        {
            if (ext is X509SubjectAlternativeNameExtension san) return san.EnumerateDnsNames();
        }
        return Array.Empty<string>();
    }

    static IEnumerable<string> IpNames(X509Certificate2 cert)
    {
        foreach (var ext in cert.Extensions)
        {
            if (ext is not X509SubjectAlternativeNameExtension san) continue;
            var names = new List<string>();
            foreach (var address in san.EnumerateIPAddresses()) names.Add(address.ToString());
            return names;
        }
        return Array.Empty<string>();
    }

    static async Task<SslStream> UpgradeWithoutSniAsync(Stream raw, List<string> notes, string label = "data")
    {
        var ssl = new SslStream(raw, false, (_, cert, _, errors) =>
        {
            // The name is not what this mode measures; the leaf's own SAN is, so accept any policy
            // verdict here and assert the identity from the certificate after the handshake.
            notes.Add($"{label} handshake leaf='{cert?.Subject}' policyErrors={errors}");
            return true;
        });
        // No target name means no server_name extension: exactly what the proxy cannot read off the wire.
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = "" });
        notes.Add($"{label} TLS={ssl.SslProtocol} alpn='{ssl.NegotiatedApplicationProtocol}'");
        return ssl;
    }

    async Task ClientRejectAsync(NetworkStream s)
    {
        await ExpectAsync(s, "220");
        await SendAsync(s, "EHLO probe\r\n");
        await ExpectMultilineAsync(s, "250");
        await SendAsync(s, "STARTTLS\r\n");
        await ExpectAsync(s, "454");
        await SendAsync(s, "NOOP\r\n");
        await ExpectAsync(s, "250");
        notes.Add("reject: the session continued in plaintext after 454");
    }

    async Task ClientPlainAsync(NetworkStream s)
    {
        await SendAsync(s, "PING\r\n");
        await ExpectAsync(s, "PONG");
        notes.Add("plain: ordinary plaintext relay still works");
    }

    static async Task ClientSmtpSplitAsync(NetworkStream s, List<string> notes)
    {
        await ExpectAsync(s, "220");
        await SendAsync(s, "EHLO split\r\n");
        await ExpectAsync(s, "250");

        // Both the command and the readiness reply straddle chunk boundaries on the wire.
        await SendAsync(s, "STAR");
        await Task.Delay(100);
        await SendAsync(s, "TTLS\r\n");
        await ExpectAsync(s, "220");

        var ssl = await UpgradeAsync(s, "probe.test", notes);
        await SendAsync(ssl, "EHLO2\r\n");
        await ExpectAsync(ssl, "250");
        notes.Add("smtpsplit: split command and split reply both handled");
    }

    static async Task ClientImplicitAsync(NetworkStream s, string host, List<string> notes)
    {
        // No plaintext phase at all: this is the HTTPS shape, where the cancelled peek is the one
        // taken on the upstream socket that SslStream must immediately reuse.
        var ssl = await UpgradeAsync(s, host, notes);
        await SendAsync(ssl, $"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
        await ExpectAsync(ssl, "HTTP/1.1 200");
        await ReadLineAsync(ssl);
        await ReadLineAsync(ssl);
        var body = new byte[2];
        var read = await ssl.ReadAsync(body);
        if (read != 2 || Encoding.ASCII.GetString(body) != "ok")
            throw new InvalidOperationException($"unexpected body ({read} bytes)");
        notes.Add($"implicit({host}): TLS MITM and relay OK");
    }

    // The upstream refuses the hello this proxy composed. A refusal can be about something the proxy
    // cannot reproduce (a demanded client certificate, a fingerprint in the raw bytes), so the session
    // has to survive it: the client's own hello is replayed to a second upstream connection. Only the
    // upstream's certificate proves that happened - a leaf from our root would mean the proxy
    // terminated a session the server had already refused.
    static async Task ClientAfterRefusalAsync(NetworkStream s, string host, List<string> notes,
        List<string> failures)
    {
        X509Certificate2? seen = null;
        using var ssl = new SslStream(s, false, (_, cert, _, _) =>
        {
            seen = cert as X509Certificate2;
            return true;
        });
        // ALPN is what forces the upstream leg first; without it the proxy answers the client before
        // it has seen the refusal, and the untranslated hello no longer exists to replay.
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = host,
            ApplicationProtocols = new List<SslApplicationProtocol>
            {
                SslApplicationProtocol.Http2,
                SslApplicationProtocol.Http11
            }
        });

        notes.Add($"mtls-refused: client TLS={ssl.SslProtocol} alpn='{ssl.NegotiatedApplicationProtocol}' " +
            $"leaf='{seen?.Subject}'");
        if (seen?.Subject.Contains("probe-upstream") != true)
            failures.Add($"mtls-refused: the client was handed '{seen?.Subject}', so the refused session " +
                "was terminated instead of relayed end to end");

        await SendAsync(ssl, $"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
        await ExpectAsync(ssl, "HTTP/1.1 200");
        await ReadLineAsync(ssl);
        await ReadLineAsync(ssl);
        var body = new byte[2];
        if (await ssl.ReadAsync(body) != 2 || Encoding.ASCII.GetString(body) != "ok")
            failures.Add("mtls-refused: the replayed hello's relay never delivered the body");
        else
            notes.Add("mtls-refused: the second upstream connection carried the client's own hello");
    }

    // The browser-shaped case: the client prefers h2, the server supports no ALPN at all. Telling the
    // client h2 here would make it send h2 frames into an http/1.1 server through a byte relay, which
    // is exactly the ERR_HTTP_PROTOCOL_ERROR the live run produced.
    static async Task ClientAlpnAsync(NetworkStream s, string host, List<string> notes)
    {
        using var ssl = new SslStream(s, false, (_, _, _, errors) => errors == SslPolicyErrors.None);
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = host,
            ApplicationProtocols = new List<SslApplicationProtocol>
            {
                SslApplicationProtocol.Http2,
                SslApplicationProtocol.Http11
            }
        });

        var negotiated = ssl.NegotiatedApplicationProtocol;
        notes.Add($"alpn: offered h2,http/1.1; proxy chose '{(negotiated == default ? "(none)" : negotiated.ToString())}'");
        if (negotiated != default)
            throw new InvalidOperationException($"proxy promised {negotiated} but the upstream negotiated no protocol");

        await SendAsync(ssl, $"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
        await ExpectAsync(ssl, "HTTP/1.1 200");
        await ReadLineAsync(ssl);
        await ReadLineAsync(ssl);
        var body = new byte[2];
        if (await ssl.ReadAsync(body) != 2 || Encoding.ASCII.GetString(body) != "ok")
            throw new InvalidOperationException("alpn-fallback body did not arrive");
        notes.Add("alpn: http/1.1 exchange completed after the upstream refused h2");
    }

    // Same client list a browser sends; asserts the proxy's client leg selects the protocol the upstream
    // selected rather than leaving the client to guess.
    static async Task ClientAlpnH2Async(NetworkStream s, string host, List<string> notes)
    {
        using var ssl = new SslStream(s, false, (_, _, _, errors) => errors == SslPolicyErrors.None);
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = host,
            ApplicationProtocols = new List<SslApplicationProtocol>
            {
                SslApplicationProtocol.Http2,
                SslApplicationProtocol.Http11
            }
        });

        var negotiated = ssl.NegotiatedApplicationProtocol;
        notes.Add($"alpn-h2: offered h2,http/1.1; proxy chose '{(negotiated == default ? "(none)" : negotiated.ToString())}'");
        if (negotiated != SslApplicationProtocol.Http2)
            throw new InvalidOperationException(
                $"client leg negotiated '{negotiated}' although the upstream selected h2");

        await SendAsync(ssl, "PINGH2\r\n");
        await ExpectAsync(ssl, "PONGH2");
        notes.Add("alpn-h2: relay works on the agreed protocol");
    }

    static async Task<SslStream> UpgradeAsync(Stream raw, string host, List<string> notes, bool acceptAny = false,
        List<SslApplicationProtocol>? offer = null)
    {
        var ssl = new SslStream(raw, false, (_, cert, chain, errors) =>
        {
            var leaf = cert as X509Certificate2;
            var root = chain is { ChainElements.Count: > 0 }
                ? chain.ChainElements[^1].Certificate.Subject
                : "(none)";
            notes.Add($"upgrade leaf='{leaf?.Subject}' errors={errors} chainDepth={chain?.ChainElements.Count ?? 0} root='{root}'");
            return acceptAny || errors == SslPolicyErrors.None;
        });
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = host,
            ApplicationProtocols = offer
        });
        notes.Add($"upgrade TLS={ssl.SslProtocol} alpn='{ssl.NegotiatedApplicationProtocol}'");
        return ssl;
    }

    static async Task ServeSmtpAsync(NetworkStream s, X509Certificate2 cert)
    {
        await SendAsync(s, "220 probe ESMTP\r\n");
        await ExpectAsync(s, "EHLO");
        await SendAsync(s, "250-probe\r\n250-STARTTLS\r\n250 OK\r\n");
        await ExpectAsync(s, "MAIL FROM");
        await SendAsync(s, "250 2.1.0 OK\r\n");
        await ExpectAsync(s, "RCPT TO");
        await SendAsync(s, "250 2.1.5 OK\r\n");
        await ExpectAsync(s, "DATA");
        await SendAsync(s, "354 End data with <CR><LF>.<CR><LF>\r\n");
        while (await ReadLineAsync(s) != ".") { }
        await SendAsync(s, "250 2.0.0 Message accepted\r\n");
        await ExpectAsync(s, "STARTTLS");
        await SendAsync(s, "220 2.0.0 Ready to start TLS\r\n");

        using var ssl = new SslStream(s, false);
        await ssl.AuthenticateAsServerAsync(cert);
        await ExpectAsync(ssl, "HELLO");
        await SendAsync(ssl, "250 TLS OK\r\n");
    }

    static async Task ServeImapAsync(NetworkStream s, X509Certificate2 cert)
    {
        await SendAsync(s, "* OK probe IMAP4rev1 ready\r\n");
        await ExpectAsync(s, "a1 CAPABILITY");
        await SendAsync(s, "* CAPABILITY IMAP4rev1 STARTTLS\r\na1 OK CAPABILITY completed\r\n");
        await ExpectAsync(s, "a2 STARTTLS");
        await SendAsync(s, "a2 OK Begin TLS negotiation now\r\n");

        using var ssl = new SslStream(s, false);
        await ssl.AuthenticateAsServerAsync(cert);
        await ExpectAsync(ssl, "a3 NOOP");
        await SendAsync(ssl, "a3 OK NOOP completed\r\n");
    }

    static async Task ServePop3Async(NetworkStream s, X509Certificate2 cert)
    {
        await SendAsync(s, "+OK probe POP3 ready\r\n");
        await ExpectAsync(s, "STLS");
        await SendAsync(s, "+OK Begin TLS negotiation\r\n");

        using var ssl = new SslStream(s, false);
        await ssl.AuthenticateAsServerAsync(cert);
        await ExpectAsync(ssl, "CAPA");
        await SendAsync(ssl, "+OK\r\n");
    }

    static async Task ServeFtpAsync(NetworkStream s, X509Certificate2 cert)
    {
        await SendAsync(s, "220 probe FTP ready\r\n");
        await ExpectAsync(s, "AUTH TLS");
        await SendAsync(s, "234 AUTH TLS successful\r\n");

        using var ssl = new SslStream(s, false);
        await ssl.AuthenticateAsServerAsync(cert);
        await ExpectAsync(ssl, "PBSZ 0");
        await SendAsync(ssl, "200 PBSZ=0\r\n");
    }

    // NNTP's grant is 382 (RFC 4642 §2.2), which the classifier now reads as readiness, so this is an
    // ordinary in-place upgrade: the proxy terminates the client leg with a leaf from the local root and
    // the upstream keeps its own certificate on the other side.
    static async Task ServeNntpAsync(NetworkStream s, X509Certificate2 cert)
    {
        await SendAsync(s, "200 probe NNTP service ready\r\n");
        await ExpectAsync(s, "STARTTLS");
        await SendAsync(s, "382 Continue with TLS negotiation\r\n");

        using var ssl = new SslStream(s, false);
        await ssl.AuthenticateAsServerAsync(cert);
        await ExpectAsync(ssl, "CAPABILITY");
        await SendAsync(ssl, "101 Capability list:\r\nVERSION 2\r\n.\r\n");
    }

    // XMPP's upgrade is an XML element on both sides (<starttls/> answered by <proceed/>, RFC 6120
    // §5.4.2.1, §5.4.2.3), so this is an in-place upgrade like the line dialects: the proxy terminates the
    // client leg with a leaf from the local root and the upstream keeps its own certificate behind the
    // grant. Every read here is byte-exact because §5.4.2.3 puts the start of the TLS negotiation after
    // the closing '>' of <proceed/> - a line-oriented read would swallow the handshake bytes behind it.
    // `split` writes one element in two pieces, which is what the scanner's cross-chunk carry is for.
    static async Task ServeXmppAsync(NetworkStream s, X509Certificate2 cert, bool split)
    {
        await ExpectBytesAsync(s, XmppClientHeader(), "initial stream header");
        await SendBytesAsync(s, XmppServerHeader());
        await SendBytesAsync(s, XmppFeatures());
        await ExpectBytesAsync(s, XmppStartTls(), "starttls command");
        await SendSplitAsync(s, XmppProceed(), split);

        using var ssl = new SslStream(s, false);
        await ssl.AuthenticateAsServerAsync(cert);

        // RFC 6120 §5.4.3.3 rule 3: the initiating entity MUST send a new initial stream header over the
        // encrypted connection, so the SASL exchange is only ever seen on the encrypted leg.
        await ExpectBytesAsync(ssl, XmppClientHeader(), "post-TLS stream header");
        await SendBytesAsync(ssl, XmppServerHeader());
        await SendBytesAsync(ssl, XmppSaslFeatures());
        await ExpectBytesAsync(ssl, XmppAuth(), "SASL auth");
        await SendBytesAsync(ssl, XmppSuccess());
    }

    static async Task ClientXmppAsync(NetworkStream s, List<string> notes, bool split)
    {
        await SendBytesAsync(s, XmppClientHeader());
        await ExpectBytesAsync(s, XmppServerHeader(), "response stream header");
        // The advertisement is a <starttls/> of this same namespace sent by the server (§5.4.1), which is
        // why the grant is looked for by its own tag and not by the command's.
        await ExpectBytesAsync(s, XmppFeatures(), "STARTTLS advertisement");

        await SendSplitAsync(s, XmppStartTls(), split);
        await ExpectBytesAsync(s, XmppProceed(), "proceed");

        var ssl = await UpgradeAsync(s, "probe.test", notes);
        await SendBytesAsync(ssl, XmppClientHeader());
        await ExpectBytesAsync(ssl, XmppServerHeader(), "post-TLS response header");
        await ExpectBytesAsync(ssl, XmppSaslFeatures(), "post-TLS SASL features");
        await SendBytesAsync(ssl, XmppAuth());
        await ExpectBytesAsync(ssl, XmppSuccess(), "SASL success");
        notes.Add(split
            ? "xmpp-split: a command and a grant each split across two writes still upgraded in place"
            : "xmpp: <starttls/> upgraded in place at the '>' that ends <proceed/>");
    }

    // The refusal half: RFC 6120 §5.4.2.2 has the server return <failure/>, close the XML stream and
    // terminate the TCP connection, and §5.4.3.2 rules out a TLS-layer failure ever looking like this, so
    // a relay that keeps carrying these octets as plaintext is the only conformant outcome.
    static async Task ServeXmppDeclineAsync(NetworkStream s)
    {
        await ExpectBytesAsync(s, XmppClientHeader(), "initial stream header");
        await SendBytesAsync(s, XmppServerHeader());
        await SendBytesAsync(s, XmppFeatures());
        await ExpectBytesAsync(s, XmppStartTls(), "starttls command");
        await SendBytesAsync(s, XmppFailure());
        await SendBytesAsync(s, XmppStreamClose());
    }

    static async Task ClientXmppDeclineAsync(NetworkStream s, List<string> notes)
    {
        await SendBytesAsync(s, XmppClientHeader());
        await ExpectBytesAsync(s, XmppServerHeader(), "response stream header");
        await ExpectBytesAsync(s, XmppFeatures(), "STARTTLS advertisement");
        await SendBytesAsync(s, XmppStartTls());
        await ExpectBytesAsync(s, XmppFailure(), "failure");
        await ExpectBytesAsync(s, XmppStreamClose(), "stream close");

        // Reading past the close is the proof no upgrade was attempted: a proxy that had read this as a
        // grant would have handed these two elements to its own handshake instead of relaying them.
        if (await s.ReadAsync(new byte[1]) != 0)
            throw new InvalidOperationException("xmpp-decline: bytes arrived after the stream closed");
        notes.Add("xmpp-decline: <failure/> was relayed and the stream ended without a TLS layer");
    }

    // The gate XMPP detection hangs on is the client's first octet, so a stream of XML that never issues
    // the RFC's command has to survive as an untouched relay. An element named starttls but qualified by
    // no TLS namespace is not that command (§5.4.2.1), and arming on it would park the client pump waiting
    // for a readiness reply that no server intends to send - the pong below can only arrive if it didn't.
    static async Task ServeXmppBadAsync(NetworkStream s)
    {
        await ExpectBytesAsync(s, XmppClientHeader(), "initial stream header");
        await SendBytesAsync(s, XmppServerHeader());
        await SendBytesAsync(s, XmppOtherFeatures());
        await ExpectBytesAsync(s, XmppUnqualifiedStartTls(), "unqualified starttls");
        await ExpectBytesAsync(s, XmppPing(), "ping");
        await SendBytesAsync(s, XmppPong());
    }

    static async Task ClientXmppBadAsync(NetworkStream s, List<string> notes)
    {
        await SendBytesAsync(s, XmppClientHeader());
        await ExpectBytesAsync(s, XmppServerHeader(), "response stream header");
        await ExpectBytesAsync(s, XmppOtherFeatures(), "stream features");
        await SendBytesAsync(s, XmppUnqualifiedStartTls());
        await SendBytesAsync(s, XmppPing());
        await ExpectBytesAsync(s, XmppPong(), "pong");
        notes.Add("xmpp-bad: a starttls element without the TLS namespace stayed an ordinary stanza");
    }

    // The verdict on a nameless XMPP hello. RFC 6120 §5.4.3.1 rule 4 lets the server choose its
    // certificate from the 'to' domainpart of the initial stream header, "functionally equivalent to the
    // Server Name Indication", and §13.7.2.1 makes that same domainpart the source of the client's
    // reference identifiers - so to='im.probe.test' is the name the leaf has to carry. A conformant
    // client may still send no server_name: §3.2.1 step 5 uses the address from the A/AAAA lookup of the
    // SRV target, and RFC 6066 §3 forbids a literal address in server_name. This mode is that client; it
    // pins the name the proxy hands it today (the destination address, which only matches an iP-ID per
    // RFC 9525 §6.2) and so fails on purpose once the leaf is named from 'to'.
    static async Task ClientXmppNoSniAsync(NetworkStream s, List<string> notes, List<string> failures)
    {
        await SendBytesAsync(s, XmppClientHeader());
        await ExpectBytesAsync(s, XmppServerHeader(), "response stream header");
        await ExpectBytesAsync(s, XmppFeatures(), "STARTTLS advertisement");
        await SendBytesAsync(s, XmppStartTls());
        await ExpectBytesAsync(s, XmppProceed(), "proceed");

        // An empty TargetHost is no server_name extension and nothing else the proxy could read a name
        // from. Any policy verdict is accepted here - the leaf's own SAN is the verdict - and the
        // post-TLS restart is carried through so a failure can only be the name, never the upgrade.
        var ssl = await UpgradeWithoutSniAsync(s, notes, "xmpp-nosni");
        await SendBytesAsync(ssl, XmppClientHeader());
        await ExpectBytesAsync(ssl, XmppServerHeader(), "post-TLS response header");
        await ExpectBytesAsync(ssl, XmppSaslFeatures(), "post-TLS SASL features");
        await SendBytesAsync(ssl, XmppAuth());
        await ExpectBytesAsync(ssl, XmppSuccess(), "SASL success");

        var leaf = ssl.RemoteCertificate as X509Certificate2;
        var dns = (leaf is null ? Array.Empty<string>() : DnsNames(leaf)).ToArray();
        var ips = (leaf is null ? Array.Empty<string>() : IpNames(leaf)).ToArray();
        notes.Add($"xmpp-nosni: leaf subject='{leaf?.Subject}' SAN dns=[{string.Join(",", dns)}] ip=[{string.Join(",", ips)}]");
        if (dns.Length != 0)
            failures.Add($"xmpp-nosni: the leaf carries DNS name(s) [{string.Join(",", dns)}] although the hello sent no server_name");
        if (!ips.Contains(IPAddress.Loopback.ToString()))
            failures.Add($"xmpp-nosni: the leaf's address SAN is [{string.Join(",", ips)}], not the destination it was dialled as");
        notes.Add("xmpp-nosni: a nameless hello was named by the destination address alone, which cannot match to='im.probe.test' (RFC 6120 §13.7.2.1) - the upgrade and the post-TLS restart work, but a client verifying the 'to' domainpart rejects");
    }

    // --- XMPP fixtures. The two stream headers carry the attributes RFC 6120 §4.7.2 and §4.7.3 require
    //     of a client stream, and the id belongs to the receiving entity's response header only.
    static byte[] XmppClientHeader() => Encoding.ASCII.GetBytes(
        "<stream:stream from='probe.test' to='im.probe.test' version='1.0'" +
        " xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>");

    static byte[] XmppServerHeader() => Encoding.ASCII.GetBytes(
        "<stream:stream from='im.probe.test' id='probe-stream-1' to='probe.test' version='1.0'" +
        " xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>");

    static byte[] XmppStartTls() => "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"u8.ToArray();
    static byte[] XmppProceed() => "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"u8.ToArray();
    static byte[] XmppFailure() => "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"u8.ToArray();
    static byte[] XmppStreamClose() => "</stream:stream>"u8.ToArray();

    // §5.4.1: an entity that supports TLS MUST advertise it, and §5.4.2 makes <required/> mark the
    // negotiation as mandatory-to-negotiate.
    static byte[] XmppFeatures() => Encoding.ASCII.GetBytes(
        "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>" +
        "</stream:features>");

    static byte[] XmppSaslFeatures() => Encoding.ASCII.GetBytes(
        "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>ANONYMOUS" +
        "</mechanism></mechanisms></stream:features>");

    // A server with no TLS support advertises something else instead, which §5.4.1 permits.
    static byte[] XmppOtherFeatures() =>
        "<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></stream:features>"u8.ToArray();

    static byte[] XmppUnqualifiedStartTls() => "<starttls/>"u8.ToArray();
    static byte[] XmppPing() => "<ping xmlns='urn:xmpp:ping'/>"u8.ToArray();
    static byte[] XmppPong() => "<pong xmlns='urn:xmpp:ping'/>"u8.ToArray();
    static byte[] XmppAuth() =>
        "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='ANONYMOUS'/>"u8.ToArray();
    static byte[] XmppSuccess() => "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>"u8.ToArray();

    static async Task SendSplitAsync(Stream s, byte[] bytes, bool split)
    {
        if (!split) { await SendBytesAsync(s, bytes); return; }
        // Cut inside the tag name, so neither the element's name nor its closing '>' is ever whole in one
        // chunk and both halves of the exchange have to be reassembled across the boundary.
        var at = 6;
        await SendBytesAsync(s, bytes[..at]);
        await Task.Delay(150);
        await SendBytesAsync(s, bytes[at..]);
    }

    // The LDAP grant path. whoami is answered first with a success ExtendedResponse of its own, so the
    // upstream has to see the StartTLS request before anything is upgraded, and the socket only becomes
    // TLS after the response the messageID names (RFC 4511 §4.14.2).
    static async Task ServeLdapAsync(NetworkStream s, X509Certificate2 cert)
    {
        await ExpectBytesAsync(s, WhoamiRequest(1), "whoami request");
        await SendBytesAsync(s, WhoamiResponse(1));
        await ExpectBytesAsync(s, StartTlsRequest(2), "StartTLS request");
        await SendBytesAsync(s, StartTlsResponse(2, 0, null));

        using var ssl = new SslStream(s, false);
        await ssl.AuthenticateAsServerAsync(cert);
        await ExpectBytesAsync(ssl, WhoamiRequest(3), "post-TLS whoami request");
        await SendBytesAsync(ssl, WhoamiResponse(3));
    }

    // The refusal stays in the plaintext session (RFC 4511 §4.14.2), so the upstream keeps reading
    // ordinary LDAP messages after it has said no.
    static async Task ServeLdapDeclineAsync(NetworkStream s)
    {
        await ExpectBytesAsync(s, WhoamiRequest(1), "whoami request");
        await SendBytesAsync(s, WhoamiResponse(1));
        await ExpectBytesAsync(s, StartTlsRequest(2), "StartTLS request");
        await SendBytesAsync(s, StartTlsResponse(2, 52, "TLS subsystem unavailable"));
        await ExpectBytesAsync(s, WhoamiRequest(3), "plaintext whoami request");
        await SendBytesAsync(s, WhoamiResponse(3));
    }

    static async Task ServeLdapBadAsync(NetworkStream s)
    {
        var junk = await ReadExactAsync(s, 2);
        if (junk[0] != 0x30 || junk[1] != 0x80)
            throw new InvalidOperationException($"expected '30 80', got '{Convert.ToHexString(junk)}'");
        await ExpectAsync(s, "PING");
        await SendAsync(s, "PONG\r\n");
    }

    // The grant path seen from the server. The call ahead of the probe is an ordinary one and is answered
    // ordinarily, so only the probe's own octets can move this socket into TLS, and the socket becomes TLS
    // after the reply that carries the probe's xid (RFC 9289 §4.1, RFC 5531 §9).
    static async Task ServeSunRpcAsync(NetworkStream s, X509Certificate2 cert, List<string> notes,
        List<string> failures, bool split, uint grantStat)
    {
        await ExpectBytesAsync(s, split ? Rpc.FragmentedCall(0x1111) : Rpc.NullCall(0x1111), "first call");
        await SendBytesAsync(s, Rpc.AcceptedReply(0x1111));
        await ExpectBytesAsync(s, split ? Rpc.FragmentedProbe(0x2222) : Rpc.Probe(0x2222), "AUTH_TLS probe");
        // The probe's own octets thrown back on the reply side, then a grant for a call this session never
        // made. Only the third record is the answer to the probe.
        await SendBytesAsync(s, Rpc.Probe(0x2222));
        await SendBytesAsync(s, Rpc.Grant(0x9999, Rpc.Success));
        await SendBytesAsync(s, Rpc.Grant(0x2222, grantStat));
        await ServeSunRpcTunnelAsync(s, cert, notes, failures);
    }

    // §4.1 refuses AUTH_TLS on any other procedure, and the refusal is about that record alone: the probe the
    // client sends next, on the NULL procedure, is granted and opens the tunnel.
    static async Task ServeSunRpcMisuseAsync(NetworkStream s, X509Certificate2 cert, List<string> notes,
        List<string> failures)
    {
        await ExpectBytesAsync(s, Rpc.AuthTlsCall(0x1111, 11), "AUTH_TLS on a non-NULL procedure");
        await SendBytesAsync(s, Rpc.Denial(0x1111));
        await ExpectBytesAsync(s, Rpc.Probe(0x2222), "AUTH_TLS probe after the refusal");
        await SendBytesAsync(s, Rpc.Grant(0x2222, Rpc.Success));
        await ServeSunRpcTunnelAsync(s, cert, notes, failures);
    }

    // The same six records seen from the server: each arrives whole and in order and is answered as the call
    // it claims to be, so the proxy has handed over nothing but octets before the probe opens the tunnel.
    static async Task ServeSunRpcNearAsync(NetworkStream s, X509Certificate2 cert, List<string> notes,
        List<string> failures)
    {
        foreach (var (xid, record) in Rpc.NearProbes())
        {
            await ExpectBytesAsync(s, record, $"near-probe 0x{xid:X4}");
            await SendBytesAsync(s, Rpc.AcceptedReply(xid));
        }
        await ExpectBytesAsync(s, Rpc.Probe(0x2222), "AUTH_TLS probe after the near-probes");
        await SendBytesAsync(s, Rpc.Grant(0x2222, Rpc.Success));
        await ServeSunRpcTunnelAsync(s, cert, notes, failures);
    }

    static async Task ServeSunRpcTunnelAsync(NetworkStream s, X509Certificate2 cert, List<string> notes,
        List<string> failures)
    {
        using var ssl = new SslStream(s, false);
        // §5 has the server put only the §7.2 identifier in its ServerHello, so the fixture offers nothing
        // else, and the proxy asked for exactly what its client offered.
        await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
        {
            ServerCertificate = cert,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            ApplicationProtocols = [Rpc.Alpn]
        });
        if (ssl.NegotiatedApplicationProtocol != Rpc.Alpn)
            failures.Add($"sunrpc(upstream): the handshake carried '{ssl.NegotiatedApplicationProtocol}' " +
                $"instead of '{Rpc.Alpn}'");
        // Measured: this host's Schannel has no TLS 1.3, so what arrives here is 1.2 even though §5 rules out
        // anything below 1.3. The proxy sets no version floor on either leg, so the version is this fixture's
        // stack talking and not the product's.
        notes.Add($"sunrpc(upstream): TLS={ssl.SslProtocol} alpn='{ssl.NegotiatedApplicationProtocol}'");

        await ExpectBytesAsync(ssl, Rpc.NullCall(0x3333), "post-TLS call");
        await SendBytesAsync(ssl, Rpc.AcceptedReply(0x3333));
    }

    // Both refusals are ordinary RPC records, so the session stays in plaintext and this server goes on
    // reading calls (RFC 9289 §4.1: operation "may continue, depending on local policy, but without
    // confidentiality, integrity, or peer authentication protection from (D)TLS").
    static async Task ServeSunRpcDeclineAsync(NetworkStream s)
    {
        await ExpectBytesAsync(s, Rpc.AuthTlsCall(0x1111, 11), "AUTH_TLS on a non-NULL procedure");
        await SendBytesAsync(s, Rpc.Denial(0x1111));
        await ExpectBytesAsync(s, Rpc.Probe(0x2222), "AUTH_TLS probe");
        await SendBytesAsync(s, Rpc.Denial(0x2222));
        await ExpectBytesAsync(s, Rpc.NullCall(0x3333), "plaintext call after the refusals");
        await SendBytesAsync(s, Rpc.AcceptedReply(0x3333));
    }

    // The server half of a reply that is MSG_ACCEPTED without being a grant: the probe is answered, then the
    // session goes on with plaintext records, which only holds if no upgrade was read into that answer.
    static async Task ServeSunRpcNoGrantAsync(NetworkStream s, byte[] answer, string label)
    {
        await ExpectBytesAsync(s, Rpc.Probe(0x2222), $"AUTH_TLS probe answered with the {label} answer");
        await SendBytesAsync(s, answer);
        await ExpectBytesAsync(s, Rpc.NullCall(0x3333), $"plaintext call after the {label} answer");
        await SendBytesAsync(s, Rpc.AcceptedReply(0x3333));
    }

    static Task ServeSunRpcBadAsync(NetworkStream s) =>
        ServeSunRpcNoGrantAsync(s, Rpc.AcceptedReply(0x2222), "no-token");

    static Task ServeSunRpcWrongTokenAsync(NetworkStream s) =>
        ServeSunRpcNoGrantAsync(s, Rpc.NotGrant(0x2222), "wrong-token");

    static Task ServeSunRpcWrongFlavorAsync(NetworkStream s) =>
        ServeSunRpcNoGrantAsync(s, Rpc.WrongFlavor(0x2222), "wrong-flavor");

    // --- LDAP fixtures. Both ends build the same octets, so every read is a byte-exact comparison
    //     instead of a second BER parser that could repeat the first one's mistake. WhoamiRequest and
    //     WhoamiResponse are the encodings RFC 4532 §2.1 and §2.2 print as their examples, down to the
    //     30 1e / 30 21 outer lengths.

    static byte[] WhoamiRequest(long messageId) =>
        LdapMessage(messageId, 0x77, Ber(0x80, Encoding.ASCII.GetBytes("1.3.6.1.4.1.4203.1.11.3")));

    static byte[] WhoamiResponse(long messageId) =>
        LdapMessage(messageId, 0x78, [.. LdapResult(0),
            .. Ber(0x8B, Encoding.ASCII.GetBytes("u:probe@example.net"))]);

    // The form wldap32 puts on the wire (measured here as 39 octets) and the form RFC 4511 §4.14.1
    // requires: requestName present, requestValue absent.
    static byte[] StartTlsRequest(long messageId) =>
        LdapMessage(messageId, 0x77, Ber(0x80, Encoding.ASCII.GetBytes("1.3.6.1.4.1.1466.20037")), 4);

    // RFC 4511 §4.14.2: the responseName is the StartTLS OID "when provided" and the responseValue is
    // always absent, so a refusal carries a name, a resultCode and a diagnostic and nothing else.
    static byte[] StartTlsResponse(long messageId, int resultCode, string? diagnostic)
    {
        var content = new List<byte>(LdapResult(resultCode, diagnostic));
        content.AddRange(Ber(0x8A, Encoding.ASCII.GetBytes("1.3.6.1.4.1.1466.20037")));
        return LdapMessage(messageId, 0x78, content.ToArray());
    }

    static byte[] LdapResult(int resultCode, string? diagnostic = null) =>
        [.. Ber(0x0A, [(byte)resultCode]), .. Ber(0x04, []),
            .. Ber(0x04, Encoding.ASCII.GetBytes(diagnostic ?? ""))];

    static byte[] LdapMessage(long messageId, byte opTag, byte[] opContent, int lengthOctets = 0) =>
        Ber(0x30, [.. Ber(0x02, [(byte)messageId]), .. Ber(opTag, opContent, lengthOctets)], lengthOctets);

    // RFC 4511 §5.1 permits only the definite form of length; lengthOctets pads that form to a chosen
    // width, which §5.1 leaves to the encoder because it constrains the form and not its width.
    static byte[] Ber(byte tag, byte[] content, int lengthOctets = 0)
    {
        if (lengthOctets == 0)
        {
            if (content.Length > 0x7F)
                throw new ArgumentOutOfRangeException(nameof(content), "fixture too long for the short form");
            return [tag, (byte)content.Length, .. content];
        }

        var head = new byte[2 + lengthOctets];
        head[0] = tag;
        head[1] = (byte)(0x80 | lengthOctets);
        for (var i = 0; i < lengthOctets; i++)
            head[2 + i] = (byte)(content.Length >> (8 * (lengthOctets - 1 - i)));
        return [.. head, .. content];
    }

    static async Task SendBytesAsync(Stream s, byte[] bytes)
    {
        await s.WriteAsync(bytes);
        await s.FlushAsync();
    }

    static async Task<byte[]> ReadExactAsync(Stream s, int count)
    {
        var buffer = new byte[count];
        var got = 0;
        while (got < count)
        {
            var n = await s.ReadAsync(buffer.AsMemory(got));
            if (n == 0) throw new EndOfStreamException($"EOF after {got} of {count} octets");
            got += n;
        }
        return buffer;
    }

    static async Task<byte[]> ExpectBytesAsync(Stream s, byte[] expected, string what)
    {
        var got = await ReadExactAsync(s, expected.Length);
        if (!got.AsSpan().SequenceEqual(expected))
            throw new InvalidOperationException(
                $"{what}: expected {Convert.ToHexString(expected)}, got {Convert.ToHexString(got)}");
        return got;
    }

    // A passive-mode FTPS session: the control channel carries the 227/229 reply, and the file itself
    // goes over a second TLS connection dialed to the ephemeral port named in that reply.
    static async Task ServeFtpDataAsync(NetworkStream s, X509Certificate2 cert, TaskCompletionSource<IPEndPoint> dataTarget, bool epsv)
    {
        await SendAsync(s, "220 probe FTP ready\r\n");
        await ExpectAsync(s, "AUTH TLS");
        await SendAsync(s, "234 AUTH TLS successful\r\n");

        using var ssl = new SslStream(s, false);
        await ssl.AuthenticateAsServerAsync(cert);
        await ExpectAsync(ssl, "PBSZ 0");
        await SendAsync(ssl, "200 PBSZ=0\r\n");
        await ExpectAsync(ssl, "PROT P");
        await SendAsync(ssl, "200 PROT set to Private\r\n");

        using var dataListener = new TcpListener(IPAddress.Loopback, 0);
        dataListener.Start();
        var dataPort = ((IPEndPoint)dataListener.LocalEndpoint).Port;
        dataTarget.SetResult(new IPEndPoint(IPAddress.Loopback, dataPort));

        await ExpectAsync(ssl, epsv ? "EPSV" : "PASV");
        if (epsv)
        {
            await SendAsync(ssl, $"229 Entering Extended Passive Mode (|||{dataPort}|)\r\n");
        }
        else
        {
            // Servers do split replies, and the two writes arrive as two relay reads, so the endpoint
            // has to be picked up from a line that straddles them. The address advertised here is the
            // private one a NAT'd server would print, not the one the client actually dials.
            await SendAsync(ssl, $"227 Entering Passive Mode (192,168,1,50,{dataPort >> 8},");
            await Task.Delay(150);
            await SendAsync(ssl, $"{dataPort & 0xFF})\r\n");
        }

        await ExpectAsync(ssl, "RETR");
        await SendAsync(ssl, "150 Opening BINARY mode data connection\r\n");

        using var dataClient = await dataListener.AcceptTcpClientAsync().WaitAsync(TimeSpan.FromSeconds(15));
        var dataSsl = new SslStream(dataClient.GetStream(), false);
        await dataSsl.AuthenticateAsServerAsync(cert);
        await dataSsl.WriteAsync(Encoding.ASCII.GetBytes("hello over ftps"));
        await dataSsl.FlushAsync();
        dataSsl.Dispose();

        await SendAsync(ssl, "226 Transfer complete\r\n");
        await ExpectAsync(ssl, "QUIT");
        await SendAsync(ssl, "221 Goodbye\r\n");
    }

    // The other half of an active-mode transfer: a server that dials whatever the control channel names,
    // and is the TLS server even though it is the one calling connect().
    static async Task ServeFtpActiveAsync(NetworkStream s, X509Certificate2 cert, List<string> notes,
        List<string> failures, TaskCompletionSource<int> listenPort, bool clear)
    {
        await SendAsync(s, "220 probe FTP ready\r\n");
        await ExpectAsync(s, "AUTH TLS");
        await SendAsync(s, "234 AUTH TLS successful\r\n");

        using var ssl = new SslStream(s, false);
        await ssl.AuthenticateAsServerAsync(cert);
        await ExpectAsync(ssl, "PBSZ 0");
        await SendAsync(ssl, "200 PBSZ=0\r\n");
        await ExpectAsync(ssl, clear ? "PROT C" : "PROT P");
        await SendAsync(ssl, "200 PROT set to private\r\n");

        var portLine = await ReadLineAsync(ssl);
        if (!portLine.StartsWith("PORT", StringComparison.OrdinalIgnoreCase))
        {
            failures.Add($"active mode: expected a PORT command, got '{portLine}'");
            return;
        }

        var target = ParsePortCommand(portLine);
        var clientPort = await listenPort.Task.WaitAsync(TimeSpan.FromSeconds(10));
        notes.Add($"ftps-active: the server was told to connect to {target.Address}:{target.Port}, the client listens on {clientPort}");
        if ((target.Port == clientPort) != clear)
        {
            failures.Add(clear
                ? "PROT C: the proxy substituted a port for a transfer it was not supposed to touch"
                : "active mode: PORT reached the server unsubstituted, so the proxy is not in this path");
            return;
        }

        await SendAsync(ssl, "200 PORT command successful\r\n");
        await ExpectAsync(ssl, "RETR");
        await SendAsync(ssl, "150 Opening BINARY mode data connection\r\n");

        using var dataTcp = new TcpClient();
        await dataTcp.ConnectAsync(target.Address, target.Port).WaitAsync(TimeSpan.FromSeconds(15));
        var dataSsl = new SslStream(dataTcp.GetStream(), false);
        await dataSsl.AuthenticateAsServerAsync(cert);
        await dataSsl.WriteAsync(Encoding.ASCII.GetBytes("hello over ftps"));
        await dataSsl.FlushAsync();
        dataSsl.Dispose();

        await SendAsync(ssl, "226 Transfer complete\r\n");
        await ExpectAsync(ssl, "QUIT");
        await SendAsync(ssl, "221 Goodbye\r\n");
    }

    // A TLS server that ends the session the way TLS expects: close_notify first, then FIN. The proxy
    // has to carry that alert across to the client, because a bare FIN is a truncation signal to
    // Schannel - the live FTPS failure was exactly "server closed abruptly (missing close_notify)".
    static async Task ServeHttpsCloseAsync(NetworkStream s, X509Certificate2 cert, List<string> notes)
    {
        using var ssl = new SslStream(s, false);
        await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
        {
            ServerCertificate = cert,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http11 }
        });

        var buf = new byte[4096];
        var read = await ssl.ReadAsync(buf).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        notes.Add($"https-close: upstream request {Encoding.ASCII.GetString(buf, 0, read).Split("\r\n")[0]}");

        // No Content-Length: the body ends when the connection does, exactly like an FTPS data
        // transfer. That forces the client to read to EOF, which is where a missing alert surfaces.
        await ssl.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nok"));
        await ssl.FlushAsync();
        await ssl.ShutdownAsync().WaitAsync(TimeSpan.FromSeconds(5));
        notes.Add("https-close: upstream sent close_notify");
    }

    // curl is the only strict TLS client on this machine: .NET's SslStream quietly accepts a bare FIN,
    // Schannel does not, and Schannel is what failed live.
    static async Task RunCurlAsync(int proxyPort, List<string> notes, List<string> failures)
    {
        var curl = File.Exists(@"C:\Windows\System32\curl.exe")
            ? @"C:\Windows\System32\curl.exe"
            : "curl.exe";
        var start = new ProcessStartInfo(curl)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (var arg in new[]
        {
            "--silent", "--show-error", "--http1.1", "--max-time", "20",
            "--noproxy", "*",
            // Name, SNI and Host stay probe.test; only the TCP peer moves, to the proxy under test.
            "--connect-to", $"probe.test:443:127.0.0.1:{proxyPort}",
            "--write-out", "\nstatus=%{http_code}",
            "https://probe.test/"
        }) start.ArgumentList.Add(arg);

        using var proc = Process.Start(start) ?? throw new InvalidOperationException("curl did not start");
        var stdoutTask = proc.StandardOutput.ReadToEndAsync();
        var stderrTask = proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(25));
        var stdout = (await stdoutTask).Trim();
        var stderr = (await stderrTask).Trim();
        notes.Add($"https-close: curl exit={proc.ExitCode} out='{stdout}' err='{stderr}'");

        if (proc.ExitCode != 0) failures.Add($"https-close: curl failed: {stderr}");
        else if (!stdout.Contains("status=200") || !stdout.Contains("ok"))
            failures.Add($"https-close: curl got no body: '{stdout}'");
    }

    // The live control leg, driven by the same Schannel client that failed on the redirector build.
    // Only the control connection is redirected; the data channel curl opens after login reaches the
    // server directly, which keeps this probe about the login relay rather than the transfer.
    static async Task RunLiveFtpsAsync(int proxyPort, string rootPemPath, string host, int port,
        string path, List<string> notes, List<string> failures)
    {
        var start = new ProcessStartInfo(@"C:\Windows\System32\curl.exe")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (var arg in new[]
        {
            "--silent", "--show-error", "--max-time", "75", "--noproxy", "*",
            "-n", "--cacert", rootPemPath,
            "--connect-to", $"{host}:{port}:127.0.0.1:{proxyPort}",
            "--write-out", "size=%{size_download} code=%{response_code}",
            $"ftps://{host}{path}"
        }) start.ArgumentList.Add(arg);

        using var proc = Process.Start(start) ?? throw new InvalidOperationException("curl did not start");
        var stdoutTask = proc.StandardOutput.ReadToEndAsync();
        var stderrTask = proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(85));
        var stdout = (await stdoutTask).Trim();
        var stderr = (await stderrTask).Trim();
        notes.Add($"live-ftps: curl exit={proc.ExitCode} out='{stdout}' err='{stderr}'");

        // Reaching the 227 reply is the assertion: the proxy relayed the greeting, the login (230),
        // PBSZ/PROT P and PASV through both legs of the MITM. curl then fails on the data channel,
        // which is not redirected here - that leg only exists in a live run.
        if (!stdout.Contains("code=227"))
            failures.Add($"live-ftps: the control leg did not reach PASV: '{stdout}' err='{stderr}'");
    }

    // A resumption that allows no ECDHE fallback: the hello offers a PSK, early_data, and psk_ke(0) alone,
    // the mode RFC 9846 §4.3.9 gives no server key_share, so there is no ephemeral secret for a proxy to
    // obtain and the session goes blind. What is under test is that the real server receives the flight -
    // the hello and the records behind it - byte for byte, and that the client still gets its reply back.
    static byte[] BuildEarlyDataFlight()
    {
        static void U16(Stream s, int v) { s.WriteByte((byte)(v >> 8)); s.WriteByte((byte)v); }
        static void Ext(Stream s, int type, byte[] data) { U16(s, type); U16(s, data.Length); s.Write(data); }

        var name = Encoding.ASCII.GetBytes("probe.test");
        var ext = new MemoryStream();

        var sni = new MemoryStream();
        U16(sni, 3 + name.Length);
        sni.WriteByte(0);
        U16(sni, name.Length);
        sni.Write(name);
        Ext(ext, 0x0000, sni.ToArray());
        Ext(ext, 0x002b, new byte[] { 4, 0x03, 0x04, 0x03, 0x03 });
        // psk_ke(0): in this mode RFC 9846 §4.3.9 has the server supply no key_share at all, so no
        // ephemeral secret exists for a proxy to obtain and the session has nothing to be terminated with.
        Ext(ext, 0x002d, new byte[] { 1, 0x00 });

        var identity = Encoding.ASCII.GetBytes("ticket-1");
        var psk = new MemoryStream();
        U16(psk, 2 + identity.Length + 4);
        U16(psk, identity.Length);
        psk.Write(identity);
        psk.Write(new byte[4]);
        U16(psk, 1 + 32);
        psk.WriteByte(32);
        psk.Write(new byte[32]);
        Ext(ext, 0x0029, psk.ToArray());
        Ext(ext, 0x002a, Array.Empty<byte>());

        var body = new MemoryStream();
        U16(body, 0x0303);
        body.Write(new byte[32]);
        body.WriteByte(0);
        U16(body, 2);
        U16(body, 0x1301);
        body.WriteByte(1);
        body.WriteByte(0);
        var extBytes = ext.ToArray();
        U16(body, extBytes.Length);
        body.Write(extBytes);
        var hello = body.ToArray();

        var flight = new MemoryStream();
        flight.WriteByte(22);
        U16(flight, 0x0301);
        U16(flight, hello.Length + 4);
        flight.WriteByte(1);
        flight.WriteByte(0);
        U16(flight, hello.Length);
        flight.Write(hello);

        var payload = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: probe.test\r\n\r\n");
        flight.WriteByte(23);
        U16(flight, 0x0303);
        U16(flight, payload.Length);
        flight.Write(payload);
        return flight.ToArray();
    }

    // The same first flight, but well-formed enough for a real stack to answer: a key_share so that a full
    // handshake is possible, supported_groups and signature_algorithms lists, a 32-byte legacy session
    // identifier, and the pre_shared_key extension last in the list where the protocol puts it. The binder
    // is 32 bytes the server cannot make sense of, so the only handshake left is the full one.
    // psk adds only the pre_shared_key extension (the key-exchange-modes list is in every one of these hellos,
    // so the legs differ by one extension each), and earlyData adds the empty early_data extension plus the
    // records a client sends before the handshake is over.
    static byte[] BuildEarlyDataHello(bool earlyData, bool psk)
    {
        static void U16(Stream s, int v) { s.WriteByte((byte)(v >> 8)); s.WriteByte((byte)v); }
        static void Ext(Stream s, int type, byte[] data) { U16(s, type); U16(s, data.Length); s.Write(data); }
        static byte[] GroupList(params int[] groups)
        {
            var m = new MemoryStream();
            U16(m, groups.Length * 2);
            foreach (var g in groups) U16(m, g);
            return m.ToArray();
        }

        var name = Encoding.ASCII.GetBytes("probe.test");
        var ext = new MemoryStream();

        var sni = new MemoryStream();
        U16(sni, 3 + name.Length);
        sni.WriteByte(0);
        U16(sni, name.Length);
        sni.Write(name);
        Ext(ext, 0x0000, sni.ToArray());
        Ext(ext, 0x000a, GroupList(0x0017));
        Ext(ext, 0x000d, GroupList(0x0804, 0x0403, 0x0401));
        Ext(ext, 0x002b, new byte[] { 4, 0x03, 0x04, 0x03, 0x03 });
        Ext(ext, 0x002d, new byte[] { 1, 0x01 });

        var shares = new MemoryStream();
        // A real key_share rather than a block of zeros, because a share the server cannot use is answered the
        // same way an extension it dislikes is. P-256 is the curve this framework will hand out coordinates
        // for; listing it in supported_groups too keeps the server from picking a group this hello has no
        // share for.
        using (var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256))
        {
            var point = ecdh.ExportParameters(false).Q;
            var x = point.X!;
            var y = point.Y!;
            var key = new byte[1 + x.Length + y.Length];
            key[0] = 4;
            x.CopyTo(key, 1);
            y.CopyTo(key, 1 + x.Length);
            U16(shares, 2 + 2 + key.Length);
            U16(shares, 0x0017);
            U16(shares, key.Length);
            shares.Write(key);
        }
        Ext(ext, 0x0033, shares.ToArray());
        if (earlyData) Ext(ext, 0x002a, Array.Empty<byte>());

        if (psk)
        {
            var identity = Encoding.ASCII.GetBytes("ticket-1");
            var pskExt = new MemoryStream();
            U16(pskExt, 2 + identity.Length + 4);
            U16(pskExt, identity.Length);
            pskExt.Write(identity);
            pskExt.Write(new byte[4]);
            U16(pskExt, 1 + 32);
            pskExt.WriteByte(32);
            pskExt.Write(new byte[32]);
            Ext(ext, 0x0029, pskExt.ToArray());
        }

        var body = new MemoryStream();
        U16(body, 0x0303);
        body.Write(new byte[32]);
        body.WriteByte(32);
        body.Write(new byte[32]);
        U16(body, 2);
        U16(body, 0x1301);
        body.WriteByte(1);
        body.WriteByte(0);
        var extBytes = ext.ToArray();
        U16(body, extBytes.Length);
        body.Write(extBytes);
        var hello = body.ToArray();

        var flight = new MemoryStream();
        flight.WriteByte(22);
        U16(flight, 0x0301);
        U16(flight, hello.Length + 4);
        flight.WriteByte(1);
        flight.WriteByte(0);
        U16(flight, hello.Length);
        flight.Write(hello);

        // RFC 9846 Appendix E.4's dummy record, then the request sent before the handshake finished. Only an
        // early-data client puts records behind its hello, so the control legs stop at the hello itself: a
        // plaintext application record in a handshake that never offered 0-RTT would be refused for a reason
        // that has nothing to do with what these legs are asking.
        if (earlyData)
        {
            flight.Write([20, 0x03, 0x03, 0x00, 0x01, 0x01]);
            var payload = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: probe.test\r\n\r\n");
            flight.WriteByte(23);
            U16(flight, 0x0303);
            U16(flight, payload.Length);
            flight.Write(payload);
        }
        return flight.ToArray();
    }

    // Each leg is a control for the next, on the socket the proxy's own terminator options would be built
    // with. A hand-written ClientHello that a stack would refuse whatever it carried would make every later
    // verdict about the encoding rather than about early data, so the first leg has neither a PSK identity
    // nor an early_data extension and has to get an answer out. The last two legs differ only in whether the
    // records behind the hello reach the terminator, which is the one thing a relay here could choose to do.
    // The client never sends a Finished, so what is read is the terminator's own first flight on the wire:
    // a ServerHello in it means the hello was accepted and the full handshake chosen, which is what refusing
    // 0-RTT would have to look like.
    static async Task CheckEarlyRefuseAsync(X509Certificate2 cert, List<string> notes, List<string> failures)
    {
        var legs = new (string Label, byte[] Flight, bool Withhold)[]
        {
            ("plain hello", BuildEarlyDataHello(false, false), false),
            ("hello with an unusable psk identity", BuildEarlyDataHello(false, true), false),
            ("early_data offered, early records given to the terminator", BuildEarlyDataHello(true, true), false),
            ("early_data offered, early records kept off the terminator", BuildEarlyDataHello(true, true), true),
        };

        // SChannel first, with a client that completes its own handshake: whether this host's SChannel can
        // negotiate 1.3 at all decides if the synthetic 1.3 hellos below mean anything for it. A 1.2-only
        // client runs alongside as the control that the certificate and options are workable, because a bare
        // "no Tls13" would otherwise be indistinguishable from a broken listener.
        var tls13 = await CheckRealClientAsync(SslProtocols.Tls13, cert);
        var tls12 = await CheckRealClientAsync(SslProtocols.Tls12, cert);
        notes.Add($"early-refuse(schannel, real client asked only for 1.3): {tls13}");
        notes.Add($"early-refuse(schannel, real client asked only for 1.2): {tls12}");
        if (!tls12.Contains("established Tls12", StringComparison.Ordinal))
            failures.Add($"early-refuse(schannel): the 1.2 control leg did not establish ('{tls12}'), " +
                         "so this harness has no working server side to test against");

        // The verdict each leg's terminator returned, kept for the comparison of the two early_data shapes.
        var byWire = new Dictionary<string, string>();

        foreach (var terminator in new[] { "schannel", "openssl" })
        {
            if (terminator == "schannel" && !tls13.Contains("established Tls13", StringComparison.Ordinal))
            {
                notes.Add("early-refuse(schannel): skipped, this host's SChannel does not negotiate TLS 1.3 " +
                          "even with a client that completes the handshake, so it never sees a 1.3 hello to refuse");
                continue;
            }

            foreach (var (label, flight, withhold) in legs)
            {
                using var probe = new TcpListener(IPAddress.Loopback, 0);
                probe.Start();
                var port = ((IPEndPoint)probe.LocalEndpoint).Port;
                var serverTask = Task.Run(async () =>
                {
                    using var accepted = await probe.AcceptTcpClientAsync();
                    var inner = accepted.GetStream();
                    // For the OpenSSL terminator the hello goes in through the replay argument the proxy
                    // already has it in, so nothing may be left in the socket for it to read twice: a second
                    // copy of the hello arrives after the handshake keys are up, which libssl reports as a
                    // record-layer error whatever the leg was meant to be measuring. SChannel reads the hello
                    // off the stream itself, so there the withheld shape is the stream that hands on one
                    // record and drops the rest.
                    Stream transport = terminator == "openssl"
                        ? new FirstRecordStream(inner, 0)
                        : withhold ? new FirstRecordStream(inner, 1) : inner;
                    var replay = terminator == "openssl" && withhold ? FirstRecord(flight) : flight;
                    try
                    {
                        if (terminator == "openssl")
                        {
                            using var stream = await OpenSslServerStream
                                .AcceptAsync(transport, replay, cert, null, null, CancellationToken.None)
                                .WaitAsync(TimeSpan.FromSeconds(8));
                            return $"established, ALPN '{stream.NegotiatedProtocol}'";
                        }
                        using var ssl = new SslStream(transport, false);
                        await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                        {
                            ServerCertificate = cert,
                            ClientCertificateRequired = false,
                            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                        }).WaitAsync(TimeSpan.FromSeconds(8));
                        return $"established {ssl.SslProtocol}";
                    }
                    catch (Exception ex)
                    {
                        return $"{ex.GetType().Name}: {ex.Message}";
                    }
                });

                using var tcp = new TcpClient();
                await tcp.ConnectAsync(IPAddress.Loopback, port);
                var net = tcp.GetStream();
                await net.WriteAsync(flight);
                await net.FlushAsync();
                var buf = new byte[16384];
                var seen = "";
                try
                {
                    var n = await net.ReadAsync(buf).AsTask().WaitAsync(TimeSpan.FromSeconds(8));
                    seen = n == 0 ? "closed with no record" : DescribeRecords(buf.AsSpan(0, n));
                }
                catch (TimeoutException)
                {
                    seen = "nothing within 8s";
                }

                // The terminator is still waiting for a Finished this client will never send, and closing the
                // socket at once would answer "what does it do with the records behind the hello" with
                // "nothing, the peer went away". So let it read what it has before the leg ends.
                await Task.Delay(TimeSpan.FromSeconds(2));
                tcp.Close();
                var verdict = await serverTask;
                byWire[$"{terminator}/{label}"] = verdict;
                notes.Add($"early-refuse({terminator}, {label}): terminator said '{verdict}'; " +
                          $"the flight it sent back was {seen}");
                if (seen == "nothing within 8s" || seen == "closed with no record")
                    failures.Add($"early-refuse({terminator}, {label}): the client leg saw '{seen}' " +
                                 $"for a {flight.Length}-byte flight");

                // A ServerHello out of the plain hello is the anchor: it says this listener, certificate and
                // encoding are workable, so any refusal after it is about what the later hello carries. The
                // two branches a server may take with a PSK it was handed are both legal - RFC 8446 §4.2.11
                // has an unknown identity "simply be ignored" and the server "perform a non-PSK handshake if
                // possible", and the same section has it abort where a binder "is not present or does not
                // validate", which Appendix E.6 notes implementations do. libssl takes the first branch. The
                // Schannel on the CI image (windows-2025-vs2026, measured 2026-11-02) sends a fatal alert for
                // all three of these hellos while answering the plain one, so a refusal here is a recorded
                // verdict about that build and not a fault of this harness.
                if (label == "plain hello" && !seen.Contains(":msg2", StringComparison.Ordinal))
                    failures.Add($"early-refuse({terminator}, {label}): no ServerHello came out ('{verdict}', {seen})" +
                        ", so every later leg on that terminator says nothing about early data");
            }
        }

        // Measured here on 2026-11-01 against the terminator that does negotiate 1.3 on this host. libssl
        // answers a hello offering early_data under an identity it cannot resolve with a ServerHello and the
        // full handshake, and the records that client put behind its hello do not upset it: the leg that hands
        // them over reaches the same point as the leg that keeps them off, which is waiting for a Finished
        // this synthetic client never sends. So refusing 0-RTT costs the terminator nothing at all. The pin is
        // the absence of a record-layer error, in both shapes, because the proxy withholds only the records
        // it already has in hand: one that arrives after the hello reaches the terminator, and the leg that
        // hands them over is what says that is survivable.
        if (byWire.TryGetValue("openssl/early_data offered, early records given to the terminator", out var passedThrough) &&
            byWire.TryGetValue("openssl/early_data offered, early records kept off the terminator", out var withheld))
        {
            if (passedThrough.Contains("bad record", StringComparison.Ordinal) ||
                withheld.Contains("bad record", StringComparison.Ordinal))
                failures.Add($"early-refuse(openssl): the early records were not tolerated, given " +
                             $"'{passedThrough}' and kept off '{withheld}'");
        }

        // What the proxy does with the fourth leg's flight: it hands the terminator the hello record and
        // keeps the rest back. Both halves are pinned, because a split that leaves one octet of the client's
        // request in the replay is the failure the branch exists to prevent, and one that cuts into the hello
        // leaves no session at all.
        var early = BuildEarlyDataHello(true, true);
        var (helloOnly, heldBack) = EarlyData.Split(early, clientOfferedEarlyData: true);
        if (heldBack.Length == 0)
        {
            failures.Add("early-refuse(split): a flight with records behind the hello held back nothing, so " +
                         "the terminator would be handed records it cannot open");
        }
        else
        {
            if (!helloOnly.SequenceEqual(FirstRecord(early)))
                failures.Add($"early-refuse(split): the replay is {helloOnly.Length} octets, not the hello " +
                             $"record's {FirstRecord(early).Length}");
            if (heldBack.Length != early.Length - FirstRecord(early).Length)
                failures.Add($"early-refuse(split): held back {heldBack.Length} of {early.Length} octets");
            // The dummy change_cipher_spec first, then the request: RFC 9846 Appendix E.4 puts that record
            // "immediately after the first ClientHello" for a client offering early data, and §4.3.10 lets
            // the application data follow it in the same flight.
            if (!DescribeRecords(heldBack).StartsWith("ccs(1) appdata(", StringComparison.Ordinal))
                failures.Add($"early-refuse(split): the records held back are {DescribeRecords(heldBack)}, " +
                             "not the dummy change_cipher_spec and the request behind it");
            if (!Encoding.ASCII.GetString(heldBack).Contains("GET / HTTP/1.1", StringComparison.Ordinal))
                failures.Add("early-refuse(split): the request is not among the records held back, so this " +
                             "flight carries no early data to withhold");
            notes.Add($"early-refuse(split): replayed {helloOnly.Length} of {early.Length} octets, held " +
                      $"back {heldBack.Length} as {DescribeRecords(heldBack)}");
        }

        // The two shapes that have to come back as one piece: a flight whose hello this proxy has not
        // finished reading, and records behind a hello that does not offer the extension. The second is what
        // makes the caller's reading of the hello load-bearing - the same octets are held back for one
        // hello and replayed for the other.
        var half = early[..(early.Length / 2)];
        var (halfOnly, halfTail) = EarlyData.Split(half, clientOfferedEarlyData: true);
        if (halfTail.Length != 0 || !halfOnly.SequenceEqual(half))
            failures.Add("early-refuse(split): a partial hello was cut at a boundary past what was read");

        var plain = BuildEarlyDataHello(false, false);
        var (plainOnly, plainTail) = EarlyData.Split(plain, clientOfferedEarlyData: true);
        if (plainTail.Length != 0 || !plainOnly.SequenceEqual(plain))
            failures.Add($"early-refuse(split): a flight that is one complete hello was cut into " +
                         $"{plainOnly.Length} and {plainTail.Length} octets");

        var unoffered = plain.Concat(heldBack).ToArray();
        var (whole, none) = EarlyData.Split(unoffered, clientOfferedEarlyData: false);
        var (cut, held) = EarlyData.Split(unoffered, clientOfferedEarlyData: true);
        if (none.Length != 0 || !whole.SequenceEqual(unoffered))
            failures.Add($"early-refuse(split): a hello offering no early_data lost {none.Length} of " +
                         $"{unoffered.Length} octets");
        if (held.Length != heldBack.Length || !cut.SequenceEqual(FirstRecord(unoffered)))
            failures.Add($"early-refuse(split): the same flight with the extension offered held back " +
                         $"{held.Length} octets instead of {heldBack.Length}");
    }

    // The ClientHello record on its own: the leg that keeps the early records off the terminator hands it
    // exactly this much of the flight.
    static byte[] FirstRecord(byte[] flight) => flight[..(5 + ((flight[3] << 8) | flight[4]))];

    // One real handshake, at the protocol the caller names, against a server built with the proxy's own
    // options, returning what each end of it saw.
    static async Task<string> CheckRealClientAsync(SslProtocols allowed, X509Certificate2 cert)
    {
        using var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        var port = ((IPEndPoint)probe.LocalEndpoint).Port;
        var serverTask = Task.Run(async () =>
        {
            using var accepted = await probe.AcceptTcpClientAsync();
            using var ssl = new SslStream(accepted.GetStream(), false);
            try
            {
                await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = cert,
                    ClientCertificateRequired = false,
                    EnabledSslProtocols = allowed,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                }).WaitAsync(TimeSpan.FromSeconds(8));
                return $"server established {ssl.SslProtocol}";
            }
            catch (Exception ex)
            {
                return $"server said {ex.GetType().Name}: {ex.Message}";
            }
        });

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, port);
        using var sslClient = new SslStream(tcp.GetStream(), false);
        try
        {
            await sslClient.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "probe.test",
                EnabledSslProtocols = allowed,
                RemoteCertificateValidationCallback = (_, _, _, _) => true,
            }).WaitAsync(TimeSpan.FromSeconds(8));
            return $"client established {sslClient.SslProtocol}; {await serverTask}";
        }
        catch (Exception ex)
        {
            return $"client failed {ex.GetType().Name}: {ex.Message}; {await serverTask}";
        }
    }

    static string DescribeRecords(ReadOnlySpan<byte> bytes)
    {
        var s = new StringBuilder();
        var offset = 0;
        while (offset + 5 <= bytes.Length)
        {
            var type = bytes[offset];
            var length = (bytes[offset + 3] << 8) | bytes[offset + 4];
            if (offset + 5 + length > bytes.Length) break;
            if (s.Length > 0) s.Append(' ');
            var label = type switch { 22 => "handshake", 20 => "ccs", 23 => "appdata", 21 => "alert", _ => $"type{type}" };
            s.Append($"{label}({length}");
            if (type == 22 && length >= 1) s.Append($":msg{bytes[offset + 5]}");
            if (type == 21 && length >= 2) s.Append($":{bytes[offset + 5]}/{bytes[offset + 6]}");
            s.Append(')');
            offset += 5 + length;
        }
        return s.Length == 0 ? $"no complete record in {bytes.Length} bytes" : s.ToString();
    }

    static async Task ServeEarlyDataAsync(NetworkStream s, byte[] expected, List<string> notes, List<string> failures)
    {
        var got = new MemoryStream();
        var buf = new byte[4096];
        while (got.Length < expected.Length)
        {
            var n = await s.ReadAsync(buf).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
            if (n == 0) break;
            got.Write(buf, 0, n);
        }

        var actual = got.ToArray();
        var intact = actual.AsSpan().SequenceEqual(expected.AsSpan(0, Math.Min(actual.Length, expected.Length)));
        if (actual.Length != expected.Length || !intact)
            failures.Add($"early-data: upstream got {actual.Length} of {expected.Length} bytes, prefix intact={intact}");
        notes.Add($"early-data: upstream received {actual.Length} bytes, first byte 0x{(actual.Length > 0 ? actual[0] : 0):X2}");

        await SendAsync(s, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    }

    static async Task ClientEarlyDataAsync(NetworkStream s, byte[] flight, List<string> notes, List<string> failures)
    {
        await s.WriteAsync(flight);
        await s.FlushAsync();

        var buf = new byte[4096];
        var n = await s.ReadAsync(buf).AsTask().WaitAsync(TimeSpan.FromSeconds(15));
        var reply = Encoding.ASCII.GetString(buf, 0, n);
        notes.Add($"early-data: {flight.Length}-byte psk_ke(0) flight relayed, reply '{reply.Split("\r\n")[0]}'");
        if (!reply.EndsWith("ok")) failures.Add($"early-data: reply was '{reply}'");
    }

    static async Task ServeRejectAsync(NetworkStream s)
    {
        await SendAsync(s, "220 probe ESMTP\r\n");
        await ExpectAsync(s, "EHLO");
        await SendAsync(s, "250-probe\r\n250-STARTTLS\r\n250 OK\r\n");
        await ExpectAsync(s, "STARTTLS");
        await SendAsync(s, "454 4.7.0 TLS not available\r\n");
        await ExpectAsync(s, "NOOP");
        await SendAsync(s, "250 OK\r\n");
    }

    static async Task ServeEchoAsync(NetworkStream s)
    {
        await ExpectAsync(s, "PING");
        await SendAsync(s, "PONG\r\n");
    }

    // Peeks instead of reading: on the relay path these same bytes have to go on to the handshake this
    // socket then attempts, and the verdict is recorded before anything can throw so a failed handshake
    // downstream cannot change it. The flight is complete once the length in the record header is covered.
    static async Task ServeEchUpstreamAsync(TcpClient accepted, X509Certificate2 cert,
        TaskCompletionSource<(int Bytes, bool Ech)> echSeen)
    {
        var buf = new byte[8192];
        var have = 0;
        var deadline = Environment.TickCount64 + 3000;
        while (Environment.TickCount64 < deadline)
        {
            var n = accepted.Client.Receive(buf, have, buf.Length - have, SocketFlags.Peek);
            if (n == 0) break;
            if (n > have) have = n;
            if (have >= 5 && have >= 5 + ((buf[3] << 8) | buf[4])) break;
            await Task.Delay(20);
        }
        echSeen.TrySetResult((have, ContainsFakeEch(buf.AsSpan(0, have))));

        using var ssl = new SslStream(accepted.GetStream(), false);
        try
        {
            await ssl.AuthenticateAsServerAsync(cert, false, SslProtocols.Tls12 | SslProtocols.Tls13, false);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Probe] ech upstream: {ex.GetType().Name}: {ex.Message}");
        }
    }

    static async Task RunEchClientAsync(int proxyPort, IPAddress ip,
        TaskCompletionSource<(int Bytes, bool Ech)> echSeen, bool expectDowngrade,
        List<string> notes, List<string> failures)
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(ip, proxyPort);
        await tcp.GetStream().WriteAsync(BuildClientHello(grease: false, ech: true));

        // Nothing is read back: the whole assertion is what the upstream socket receives, and a synthetic
        // hello cannot finish a handshake from this side anyway.
        var (bytes, reached) = await echSeen.Task.WaitAsync(TimeSpan.FromSeconds(8));
        var name = expectDowngrade ? "ech-downgrade" : "ech-relay";
        if (bytes == 0)
        {
            failures.Add($"{name}: the upstream received no ClientHello at all");
            return;
        }
        notes.Add($"{name}: {bytes} bytes reached the upstream, ECH extension {(reached ? "present" : "absent")}");

        if (expectDowngrade)
        {
            if (reached) failures.Add("ech-downgrade: the upstream still saw the client's ECH hello");
            else notes.Add("ech-downgrade: the upstream saw the proxy's own hello, the ECH hello was terminated");
        }
        else
        {
            if (!reached) failures.Add("ech-relay: the client's ECH hello never reached the upstream");
            else notes.Add("ech-relay: the client's ECH hello reached the upstream verbatim");
        }
    }

    // The synthetic extension's own bytes, not merely its type - finding 0xFE0D would also be satisfied by
    // a proxy that rewrote the extension's contents.
    static bool ContainsFakeEch(ReadOnlySpan<byte> hello)
    {
        for (var i = 0; i + 7 < hello.Length; i++)
            if (hello[i] == 0xFE && hello[i + 1] == 0x0D && hello[i + 2] == 0x00 && hello[i + 3] == 0x08
                && hello[i + 4] == 0xE0 && hello[i + 5] == 0x01 && hello[i + 6] == 0x02 && hello[i + 7] == 0x03)
                return true;
        return false;
    }

    static async Task ServeSmtpSplitAsync(NetworkStream s, X509Certificate2 cert)
    {
        await SendAsync(s, "220 probe ESMTP\r\n");
        await ExpectAsync(s, "EHLO");
        await SendAsync(s, "250 probe\r\n");
        await ExpectAsync(s, "STARTTLS");

        await SendAsync(s, "220 2.0.0 Rea");
        await Task.Delay(150);
        await SendAsync(s, "dy to start TLS\r\n");

        using var ssl = new SslStream(s, false);
        await ssl.AuthenticateAsServerAsync(cert);
        await ExpectAsync(ssl, "EHLO2");
        await SendAsync(ssl, "250 TLS OK\r\n");
    }

    static async Task ServeImplicitAsync(NetworkStream s, X509Certificate2 cert)
    {
        using var ssl = new SslStream(s, false);
        await ssl.AuthenticateAsServerAsync(cert);
        await ExpectRequestHeadAsync(ssl);
        await SendAsync(ssl, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    }

    // Reads the whole ClientHello record, then refuses it the way a server that wants a client
    // certificate does: a fatal alert, description 40 (handshake_failure, RFC 8446 §6.2), and close.
    // The size is worth printing: it is the only evidence that a hello arrived instead of the proxy
    // giving up before sending one.
    static async Task ServeRefuseHandshakeAsync(NetworkStream s, List<string> notes)
    {
        var header = new byte[5];
        await s.ReadExactlyAsync(header);
        var bodyLength = (header[3] << 8) | header[4];
        if (header[0] != 0x16 || bodyLength <= 0 || bodyLength > 0x4000)
            throw new IOException($"expected a ClientHello record, got type {header[0]} length {bodyLength}");
        await s.ReadExactlyAsync(new byte[bodyLength]);
        notes.Add($"mtls-refused: fake upstream read a {5 + bodyLength}-byte ClientHello and refused it");
        await s.WriteAsync(new byte[] { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28 });
        await s.FlushAsync();
    }

    // A real HTTP server answers only after the blank line that ends the header block, so waiting for it
    // is what catches a relay that withholds the tail of the request. Measured: the FTP control sniffer
    // held the last two bytes of every bodyless GET, and a tolerant fake upstream hid it for weeks.
    static async Task ExpectRequestHeadAsync(Stream s)
    {
        var buf = new byte[1024];
        var got = 0;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try
        {
            while (true)
            {
                if (got >= 4 && Encoding.ASCII.GetString(buf, got - 4, 4) == "\r\n\r\n") return;
                var n = await s.ReadAsync(buf.AsMemory(got), cts.Token);
                if (n == 0) throw new IOException($"request ended after {got} bytes without its blank line");
                got += n;
                if (got == buf.Length) throw new IOException("request head outgrew the probe buffer");
            }
        }
        catch (OperationCanceledException)
        {
            throw new IOException($"request head never completed: {got} bytes, no blank line");
        }
    }

    // The emSign client exits the moment the body arrives, so this leg can be aborted mid-write; whether
    // the client's store trusted the chain is judged from what the client reported, not from here.
    static async Task ServeOptionalImplicitAsync(NetworkStream s, X509Certificate2 cert)
    {
        try
        {
            await ServeImplicitAsync(s, cert);
        }
        catch (Exception ex) when (ex is IOException or AuthenticationException) { }
    }

    // --- the media dialects that begin with TLS --------------------------------------------------------
    //
    // RFC 7826 §4.2: the scheme "rtsps" identifies "a reliable transport using secure transport (TLS
    // [RFC5246])" and "if no port number is provided in the authority part of the URI ... the TCP port 322
    // MUST be used". RFC 3261 §5 Table 1 note (1): the default port "is 5061 for sip: using TLS over TCP and
    // sips: over TCP". Neither protocol has an in-band upgrade, so both arrive in the shape `implicit-ip`
    // already covers - first octet 0x16, and the client leg answered first because no ALPN was offered. What
    // is new is the payload behind the tunnel, and each of these three modes now carries a whole session
    // scripted in Media: RTSP's DESCRIBE/SETUP/PLAY with interleaved blocks on the channels the server's own
    // answer chose, RTMP's chunk stream after the three handshake blocks, and SIP's registration and dialog
    // progressions with bodies, a provisional response before the 200, and a bare-CRLF keep-alive. Every turn
    // of every dialect is then judged by each end of the tunnel and again from the file the product wrote.

    // The scripted media upstreams all answer the same way: terminate TLS with the fixture's own leaf, run
    // this half of the script, then report the server name the proxy offered when it dialled, the protocol
    // the client leg settled on, and how many turns arrived whole. The turn count travels with the verdict:
    // a session that stopped at turn 3 of 17 is a different answer from one that never got past turn 1.
    async Task ServeScriptedAsync(TcpClient accepted, X509Certificate2 cert, List<MediaTurn> script,
        string label, List<string> serverNotes, List<string> serverFailures)
    {
        var options = new SslServerAuthenticationOptions { ServerCertificate = cert };
        using var ssl = new SslStream(accepted.GetStream(), false);
        string? offered = null;
        var protocol = "";
        var turns = 0;
        try
        {
            await ssl.AuthenticateAsServerAsync(options).WaitAsync(TimeSpan.FromSeconds(25));
            offered = ssl.TargetHostName;
            protocol = ssl.SslProtocol.ToString();
            serverNotes.Add($"{label}(upstream): terminated {protocol} offered name '{OfferedName(offered)}'");
            turns = await Media.RunDialogue(ssl, script, asClient: false, $"{label}(upstream)",
                serverNotes, serverFailures);
        }
        catch (Exception ex) when (ex is IOException or AuthenticationException or TimeoutException
                                       or OperationCanceledException or EndOfStreamException)
        {
            serverNotes.Add($"{label}(upstream): ended after {turns} turn(s) " +
                            $"({ex.GetType().Name}: {ex.Message})");
        }
        dialogueDone.TrySetResult((offered, protocol, turns));
    }

    // The client half of the same script, so the two ends cannot disagree about what was sent. What is pinned
    // here is what this end saw: the tunnel came up with no server_name, so the leaf has to be named from the
    // destination address; each turn of the far half is read where its own dialect says the message ends; and
    // the capture the product wrote for the session holds the dialogue decrypted in order per direction. The
    // "(none)" in the naming note is made meaningful by CheckSniVisibilityAsync, run before this for rtsps.
    async Task ClientScriptedAsync(NetworkStream s, List<MediaTurn> script, string label,
        List<string> notes, List<string> failures)
    {
        var ssl = await UpgradeWithoutSniAsync(s, notes, label);
        var turns = await Media.RunDialogue(ssl, script, asClient: true, label, notes, failures);
        CheckAddressLeaf(ssl, label, notes, failures);
        var (offered, protocol, upstreamTurns) = await dialogueDone.Task.WaitAsync(TimeSpan.FromSeconds(20));
        notes.Add($"{label}: upstream was offered name '{OfferedName(offered)}' and terminated {protocol}; it " +
                  $"read {upstreamTurns} of {script.Count} turns, this end completed {turns}");
        if (upstreamTurns != script.Count)
            failures.Add($"{label}: the upstream read only {upstreamTurns} of {script.Count} turns");
        await Capture.CheckDialogueAsync(capturesBefore, upstreamPort, script, label, notes, failures);
    }

    // The fake upstream for a real media client. It cannot be handed a fixed flight, because nothing here
    // dictates what a third-party client puts on the wire, so it answers the dialect's own exchanges one
    // block at a time and keeps the first two for the client side to judge. RTMP has no header at all,
    // only the fixed block sizes.
    async Task ServeMediaClientUpstreamAsync(TcpClient accepted, X509Certificate2 cert,
        TaskCompletionSource<(string? Offered, byte[] First, byte[] Second)> mediaSeen,
        List<string> serverNotes, List<string> serverFailures)
    {
        var options = new SslServerAuthenticationOptions { ServerCertificate = cert };
        using var ssl = new SslStream(accepted.GetStream(), false);
        string? offered = null;
        byte[] first = Array.Empty<byte>(), second = Array.Empty<byte>();
        try
        {
            await ssl.AuthenticateAsServerAsync(options).WaitAsync(TimeSpan.FromSeconds(25));
            offered = ssl.TargetHostName;
            serverNotes.Add($"{mode}(upstream): terminated {ssl.SslProtocol} for name '{OfferedName(offered)}'");
            (first, second) = await ServeRtmpClientHandshakeAsync(ssl, serverNotes, serverFailures, mode);
        }
        catch (Exception ex) when (ex is IOException or AuthenticationException or TimeoutException
                                       or OperationCanceledException or EndOfStreamException)
        {
            serverNotes.Add($"{mode}(upstream): ended ({ex.GetType().Name}: {ex.Message})");
        }
        mediaSeen.TrySetResult((offered, first, second));
    }

    async Task<(byte[] First, byte[] Second)> ServeRtmpClientHandshakeAsync(SslStream ssl,
        List<string> serverNotes, List<string> serverFailures, string label)
    {
        // The client's first block is 1537 octets with no structure a reader could stop on, so the fixture
        // is driven by size alone: one block in, its own version byte plus random back, the client's answer,
        // and S2 to close the handshake - a client that never gets it stays inside the handshake and puts no
        // chunk stream on the wire (measured 2026-11-03: with three blocks served, the octets after C2 were
        // the beginning of the connect command taken as S2).
        var s0s1 = await Media.ReadUpTo(ssl, 1537, TimeSpan.FromSeconds(25));
        if (s0s1.Length != 1537 || s0s1[0] != 0x03)
            serverFailures.Add($"{label}(upstream): the client's first block arrived as {s0s1.Length} octets " +
                               $"beginning 0x{(s0s1.Length > 0 ? s0s1[0].ToString("x2") : "??")}");
        var reply = new byte[1537];
        reply[0] = 0x03;
        RandomNumberGenerator.Fill(reply.AsSpan(1));
        await ssl.WriteAsync(reply);
        await ssl.FlushAsync();

        var c2 = await Media.ReadUpTo(ssl, 1536, TimeSpan.FromSeconds(10));
        if (c2.Length < 1536)
            serverFailures.Add($"{label}(upstream): the client answered with {c2.Length} octets, fewer than " +
                               "the 1536 its second handshake block holds");
        // S2 echoes the client's own C1, which is what a real server puts there.
        await ssl.WriteAsync(s0s1.AsMemory(1, 1536));
        await ssl.FlushAsync();

        // Point the reader that judges the fixture's own dialogue at a third party's bytes. What the client
        // puts on the wire after the handshake closes has to frame as a message under the vendor's chunk
        // layout, and only its first command names itself: a reader both ends of one fixture wrote could
        // agree on a framing this does not expose.
        var reader = new RtmpChunks(ssl);
        var framed = new List<RtmpMessage>();
        using var chunkClock = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        string? method = null;
        try
        {
            while (method == null)
            {
                var arrived = await reader.ReadUntil(1).WaitAsync(chunkClock.Token);
                var message = arrived.Messages[0];
                framed.Add(message);
                if (message.Type == Media.RtmpCommand)
                    method = Media.AmfMethod(message.Body) ??
                             $"(a command whose body opens {Convert.ToHexString(message.Body[..Math.Min(message.Body.Length, 8)])})";
            }
        }
        catch (Exception ex) when (ex is IOException or EndOfStreamException or OperationCanceledException
                                       or InvalidDataException)
        {
            serverNotes.Add($"{label}(upstream): its chunk stream stopped after {framed.Count} message(s) " +
                            $"({ex.GetType().Name}: {ex.Message})");
        }
        if (method != null)
            serverNotes.Add($"{label}(upstream): the client's first command framed as '{method}' on chunk stream " +
                            $"{framed[^1].Csid}, stream {framed[^1].StreamId}, {framed[^1].Body.Length} body octets, " +
                            $"{framed.Count} message(s) in all");
        return (s0s1, c2);
    }

    // The media client that is not this harness: a foreign TLS stack, its own handshake octets, and a second
    // process for the product to attribute by pid. rtsps:// is not driven from here - that path asks its lower
    // transport for a socket handle before writing any RTSP octet, and the tls transport has none to give, so
    // the run ends with "Operation not permitted" having sent nothing, the product in the path or out
    // (measured). The RTSP dialect itself is pinned by the rtsps mode, which needs no third-party binary.
    static async Task RunFfmpegMediaClientAsync(string mode, int proxyPort, string ffmpeg,
        TaskCompletionSource<(string? Offered, byte[] First, byte[] Second)> mediaSeen,
        List<string> notes, List<string> failures)
    {
        // The client dials the proxy's listener exactly as every other mode's client does; the fake
        // redirector still decides where the proxy's upstream leg lands.
        var url = $"rtmps://127.0.0.1:{proxyPort}/live/stream";
        var arguments = $"-hide_banner -loglevel info -f lavfi -i color=c=black:s=16x16:r=1 -t 1 -f flv {url}";
        var psi = new ProcessStartInfo(ffmpeg, arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        Process process;
        try
        {
            process = Process.Start(psi) ?? throw new InvalidOperationException("could not start ffmpeg");
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            failures.Add($"{mode}: TLSMITM_FFMPEG does not name a runnable binary ({ex.Message})");
            return;
        }

        using (process)
        {
            var log = process.StandardError.ReadToEndAsync();
            (string? Offered, byte[] First, byte[] Second) seen;
            try
            {
                seen = await mediaSeen.Task.WaitAsync(TimeSpan.FromSeconds(45));
            }
            catch (TimeoutException)
            {
                failures.Add($"{mode}: the real client's session never reached the fake upstream");
                await ReportFfmpegLogAsync(log, process, notes, failures, mode, kill: true);
                return;
            }

            notes.Add($"{mode}: the upstream leg was dialled for name '{OfferedName(seen.Offered)}' and the " +
                      $"client's first two blocks were {seen.First.Length} then {seen.Second.Length} octets");
            if (seen.First.Length != 1537 || seen.First[0] != 0x03)
                failures.Add($"{mode}: the client's handshake block reached the upstream as {seen.First.Length} " +
                             "octets, not the 1537 the RTMP client sends first");
            else notes.Add($"{mode}: the client's block arrived whole, 1537 octets opening with the version byte");

            await ReportFfmpegLogAsync(log, process, notes, failures, mode, kill: false);
        }
    }

    // The fixture is a control-plane server, not a media source, so what ffmpeg decides to do with the rest
    // of the session is recorded rather than required - except a process that never ends on its own, which
    // is reported as a failure because that is what a relay that swallowed a block looks like from here.
    static async Task ReportFfmpegLogAsync(Task<string> log, Process process, List<string> notes,
        List<string> failures, string mode, bool kill)
    {
        var ended = false;
        try
        {
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(20));
            ended = true;
        }
        catch (TimeoutException) { }
        if (kill || !ended)
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
        }
        if (!ended) failures.Add($"{mode}: ffmpeg was still running 20s after its session ended upstream");
        var text = await log;
        foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries).TakeLast(4))
            notes.Add($"{mode}(ffmpeg): {line.Trim()}");
    }

    // The media modes report what the far end was told, so the channel carrying that answer needs a positive
    // control: a name a client does send must be what the server reads back. Without it, the "(none)" a media
    // mode reports says nothing about the client and everything about the harness.
    static async Task CheckSniVisibilityAsync(X509Certificate2 cert, List<string> notes, List<string> failures)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var client = new TcpClient();
        var accepted = listener.AcceptTcpClientAsync();
        await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
        var serverSide = new SslStream((await accepted).GetStream(), false);
        var clientSide = new SslStream(client.GetStream(), false);
        await Task.WhenAll(
            serverSide.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = cert }),
            clientSide.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "probe.test",
                RemoteCertificateValidationCallback = (_, _, _, _) => true
            }));
        notes.Add($"sni-control: a client that sent 'probe.test' was read back as " +
                  $"'{OfferedName(serverSide.TargetHostName)}'");
        if (serverSide.TargetHostName != "probe.test")
            failures.Add("sni-control: the server side could not read back the name the client sent, so the " +
                         "'(none)' a media mode reports is not evidence about the client");
        serverSide.Dispose();
        clientSide.Dispose();
        listener.Stop();
    }

    // SslStream reports an empty string for a hello that carried no server_name; naming it in one place keeps
    // the log readable and the difference from a real name unambiguous.
    static string OfferedName(string? name) => string.IsNullOrEmpty(name) ? "(none)" : name;

    // A session with no server_name is named from the address the client was dialling: SNI carries domain
    // names only (RFC 6066 §3; RFC 9525 §7.4), and the reference identifier for an IP-dialing client is an
    // iP-ID, which RFC 9525 §6.2 matches solely against iPAddress SAN entries, octet-for-octet (§6.4). A DNS
    // name on this leaf would therefore be a certificate no client of that shape can accept.
    static void CheckAddressLeaf(SslStream ssl, string label, List<string> notes, List<string> failures)
    {
        if (ssl.RemoteCertificate is not X509Certificate2 leaf)
        {
            failures.Add($"{label}: no certificate reached the client, so the naming decision is unseen");
            return;
        }
        var dns = string.Join(",", DnsNames(leaf));
        var ip = string.Join(",", IpNames(leaf));
        notes.Add($"{label}: leaf subject='{leaf.Subject}' SAN dns=[{dns}] ip=[{ip}]");
        if (dns.Length > 0 || !ip.Contains("127.0.0.1"))
            failures.Add($"{label}: a session with no server_name was named dns=[{dns}] ip=[{ip}] instead of " +
                         "the destination address");
    }

    // The mirror image of alpn-fallback, and the case that was missing while the ALPN bug shipped: the
    // real servers (bing, bilibili) do select h2, so the client leg has to be told h2 as well.
    static async Task ServeImplicitH2Async(NetworkStream s, X509Certificate2 cert)
    {
        using var ssl = new SslStream(s, false);
        await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
        {
            ServerCertificate = cert,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http2 }
        });
        if (ssl.NegotiatedApplicationProtocol != SslApplicationProtocol.Http2)
            throw new InvalidOperationException($"upstream did not negotiate h2 ({ssl.NegotiatedApplicationProtocol})");
        await ExpectAsync(ssl, "PINGH2");
        await SendAsync(ssl, "PONGH2\r\n");
    }

    static async Task SendAsync(Stream s, string text)
    {
        await s.WriteAsync(Encoding.ASCII.GetBytes(text));
        await s.FlushAsync();
    }

    static async Task<string> ReadLineAsync(Stream s)
    {
        var sb = new StringBuilder();
        var one = new byte[1];
        while (true)
        {
            var n = await s.ReadAsync(one);
            if (n == 0) throw new EndOfStreamException($"EOF while reading a line (got '{sb}')");
            if (one[0] == (byte)'\n') return sb.ToString();
            if (one[0] != (byte)'\r') sb.Append((char)one[0]);
        }
    }

    static async Task ExpectAsync(Stream s, string prefix)
    {
        var line = await ReadLineAsync(s);
        if (!line.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"expected '{prefix}', got '{line}'");
    }

    static async Task ExpectMultilineAsync(Stream s, string codePrefix)
    {
        string line;
        do { line = await ReadLineAsync(s); } while (!line.StartsWith(codePrefix + " "));
    }

    // pcap layout: a 24-byte global header, then per packet a 16-byte record header and the Ethernet
    // frame. Reading the first record is enough to tell which network layer the writer emitted.
    static async Task CheckIpv6CaptureAsync(string[] before, List<string> notes, List<string> failures)
    {
        var path = await Capture.FindAsync(before, _ => true);
        if (path == null)
        {
            failures.Add("ipv6: no capture file was written");
            return;
        }

        const int frame = 24 + 16;
        var bytes = await Capture.ReadAsync(path);
        if (bytes.Length < frame + 14 + 40)
        {
            failures.Add($"ipv6: capture {Path.GetFileName(path)} is too short ({bytes.Length} bytes)");
            return;
        }
        if (bytes[frame + 12] != 0x86 || bytes[frame + 13] != 0xDD)
        {
            failures.Add($"ipv6: capture is not IPv6 (EtherType {bytes[frame + 12]:X2}{bytes[frame + 13]:X2})");
            return;
        }
        if (bytes[frame + 14] >> 4 != 6 || bytes[frame + 14 + 6] != 6)
        {
            failures.Add("ipv6: capture header is not IPv6/TCP");
            return;
        }

        var src = new IPAddress(bytes.AsSpan(frame + 14 + 8, 16));
        var dst = new IPAddress(bytes.AsSpan(frame + 14 + 24, 16));
        notes.Add($"ipv6: capture {Path.GetFileName(path)} carries IPv6, {src} -> {dst}");
    }

    static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    // The emSign material is the product's own: the same intermediates the proxy signs with and the same
    // cross-signed root it ships, so the client leg is judged against what a real run would send.
    static List<EmSignCa> LoadEmSignCas()
    {
        var cas = new List<EmSignCa>();
        var baseDir = Path.Combine(AppContext.BaseDirectory, "emsign_certs");
        var interDir = Path.Combine(baseDir, "intermediates");
        var chainDir = Path.Combine(baseDir, "chain");
        if (!Directory.Exists(interDir))
        {
            Console.WriteLine($"[Probe] no emSign intermediates at {interDir}");
            return cas;
        }

        var chainPaths = Directory.Exists(chainDir) ? Directory.GetFiles(chainDir) : Array.Empty<string>();
        foreach (var path in Directory.GetFiles(interDir))
        {
            using var probe = X509CertificateLoader.LoadCertificate(File.ReadAllBytes(path));
            var cn = probe.GetNameInfo(X509NameType.SimpleName, false);
            var known = EmSignCa.KnownIntermediates.FirstOrDefault(k => k.Name == cn);
            if (known.Name == null) continue;
            cas.Add(EmSignCa.LoadFromPem(cn!, known.Scalar, path, chainPaths));
        }
        Console.WriteLine($"[Probe] loaded {cas.Count} emSign intermediates");
        return cas;
    }

    // The Windows-store half of the auto-mode decision. SChannel validates the leaf against the local
    // store, so the only way this handshake can succeed is if the engine chose the Fiddler root for a
    // client it did not classify as Node/Electron.
    static async Task ClientFiddlerAsync(NetworkStream s, string host, List<string> notes)
    {
        var chainRoot = "(none)";
        using var ssl = new SslStream(s, false, (_, _, chain, errors) =>
        {
            chainRoot = chain is { ChainElements.Count: > 0 }
                ? chain.ChainElements[^1].Certificate.Subject
                : "(none)";
            return errors == SslPolicyErrors.None;
        });
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = host });
        notes.Add($"auto: probe's own client got root='{chainRoot}' errors=None");
        if (!chainRoot.Contains("DO_NOT_TRUST_FiddlerRoot", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                $"a Windows-store client was not served the Fiddler chain (root='{chainRoot}')");

        await SendAsync(ssl, $"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
        await ExpectAsync(ssl, "HTTP/1.1 200");
        await ReadLineAsync(ssl);
        await ReadLineAsync(ssl);
        var body = new byte[2];
        if (await ssl.ReadAsync(body) != 2 || Encoding.ASCII.GetString(body) != "ok")
            throw new InvalidOperationException("auto: Fiddler-chain client body did not arrive");
        notes.Add("auto: Windows-store client verified against the Fiddler root and the relay completed");
    }

    // The per-connection half of the chain decision: a process that hosts both TLS stacks is told apart
    // by its ClientHello. Synthetic hellos exercise the parser without needing a real Chromium client.
    static async Task CheckGreaseAsync(List<string> notes, List<string> failures)
    {
        var parser = typeof(MitmProxy).GetMethod("ReadClientHelloAsync",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        var resolve = typeof(MitmProxy).GetMethod("ResolveTrust",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;

        async Task<object> ParseAsync(byte[] flight)
        {
            using var stream = new MemoryStream(flight, 1, flight.Length - 1);
            var task = (Task)parser.Invoke(null, new object?[] { stream, flight[0], CancellationToken.None })!;
            await task;
            var tuple = task.GetType().GetProperty("Result")!.GetValue(task)!;
            return tuple.GetType().GetField("Item1")!.GetValue(tuple)!;
        }

        var chromium = await ParseAsync(BuildClientHello(grease: true));
        var node = await ParseAsync(BuildClientHello(grease: false));
        if (chromium == null || node == null)
        {
            failures.Add("grease: a synthetic ClientHello failed to parse");
            return;
        }

        var chromiumGrease = (bool)chromium.GetType().GetProperty("Grease")!.GetValue(chromium)!;
        var nodeGrease = (bool)node.GetType().GetProperty("Grease")!.GetValue(node)!;
        var sn = (string?)node.GetType().GetProperty("ServerName")!.GetValue(node);
        var alpn = (IReadOnlyList<string>)node.GetType().GetProperty("Alpn")!.GetValue(node)!;
        notes.Add($"grease: parsed chromium={chromiumGrease} node={nodeGrease} sni='{sn}' alpn='{string.Join(",", alpn)}'");

        if (!chromiumGrease) failures.Add("grease: a hello with a GREASE cipher was not recognised");
        if (nodeGrease) failures.Add("grease: a hello without GREASE was misread as Chromium");
        if (sn != "probe.test") failures.Add($"grease: SNI was not parsed (got '{sn}')");
        if (!alpn.Contains("http/1.1")) failures.Add("grease: ALPN was not parsed");

        var ambiguous = new ClientIdentity(ClientTrust.NodeBundled, 1, "test", true, "code.exe");
        var decided = (ClientTrust)resolve.Invoke(null, new object?[] { ambiguous, chromium })!;
        var kept = (ClientTrust)resolve.Invoke(null, new object?[] { ambiguous, node })!;
        if (decided != ClientTrust.WindowsStore)
            failures.Add("grease: an ambiguous process sending GREASE was not moved to the Fiddler chain");
        if (kept != ClientTrust.NodeBundled)
            failures.Add("grease: an ambiguous process without GREASE lost its emSign chain");
        notes.Add($"grease: ambiguous pid -> chromium='{decided}' node='{kept}'");

        // A client with no PID - every forwarded LAN client - has no local process to judge it by, so
        // --emsign has to give it the same chain --emsign-only gives everyone.
        var chain = typeof(MitmProxy).GetMethod("ChainIdentity",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        var unowned = new ClientIdentity(ClientTrust.WindowsStore, 0, "unknown (no TCP owner)", false, "");
        var remote = (ClientIdentity)chain.Invoke(null,
            new object?[] { unowned, IPAddress.Parse("192.168.122.50") })!;
        if (remote.Trust != ClientTrust.NodeBundled || remote.Ambiguous)
            failures.Add("grease: a client with no PID on the LAN did not get the emSign chain");
        if (remote.Label != "remote client (no process on this machine)")
            failures.Add($"grease: a LAN client with no PID was labelled '{remote.Label}'");
        var local = (ClientIdentity)chain.Invoke(null, new object?[] { unowned, IPAddress.Loopback })!;
        if (local.Trust != ClientTrust.NodeBundled)
            failures.Add("grease: a local flow with no PID did not get the emSign chain");
        var owned = new ClientIdentity(ClientTrust.WindowsStore, 4242, "curl.exe", false, "curl.exe");
        var keptOwned = (ClientIdentity)chain.Invoke(null,
            new object?[] { owned, IPAddress.Parse("192.168.122.50") })!;
        if (keptOwned.Trust != ClientTrust.WindowsStore || keptOwned.Label != "curl.exe")
            failures.Add("grease: a client with a PID lost its per-process chain");
        notes.Add($"grease: no pid -> remote='{remote.Trust}' local='{local.Trust}' owned='{keptOwned.Trust}'");
    }

    // Minimal but structurally valid ClientHello: TLS 1.2 record, SNI and ALPN present, and optionally a
    // GREASE cipher suite in the list, which is the only marker that separates Chromium from Node. The
    // ECH option appends a fake encrypted_client_hello (0xfe0d, RFC 9849 §5) whose payload is recognisable
    // on the far side; it is a marker rather than a well-formed EncryptedClientHello, because nothing on
    // either side has to decrypt it.
    static byte[] BuildClientHello(bool grease, bool ech = false)
    {
        var body = new List<byte> { 0x03, 0x03 };
        body.AddRange(new byte[32]);
        body.Add(0x00); // empty session id
        var suites = grease ? new byte[] { 0x1A, 0x1A, 0x13, 0x01 } : new byte[] { 0x13, 0x01, 0xC0, 0x2F };
        body.Add((byte)(suites.Length >> 8)); body.Add((byte)suites.Length);
        body.AddRange(suites);
        body.Add(0x01); body.Add(0x00); // null compression

        var extensions = new List<byte>();

        // server_name: list length (2), name type host_name (1), name length (2), name.
        var name = Encoding.ASCII.GetBytes("probe.test");
        extensions.AddRange(new byte[] { 0x00, 0x00, 0x00, (byte)(name.Length + 5) });
        extensions.AddRange(new byte[] { (byte)((name.Length + 3) >> 8), (byte)(name.Length + 3) });
        extensions.Add(0x00);
        extensions.Add((byte)(name.Length >> 8)); extensions.Add((byte)name.Length);
        extensions.AddRange(name);

        // application_layer_protocol_negotiation: list length (2), then length-prefixed entries.
        var protocols = Encoding.ASCII.GetBytes("http/1.1");
        var alpnData = new List<byte> { (byte)((protocols.Length + 1) >> 8), (byte)(protocols.Length + 1), (byte)protocols.Length };
        alpnData.AddRange(protocols);
        extensions.AddRange(new byte[] { 0x00, 0x10, (byte)(alpnData.Count >> 8), (byte)alpnData.Count });
        extensions.AddRange(alpnData);

        // encrypted_client_hello: type 0xfe0d with eight recognizable payload octets.
        if (ech)
        {
            extensions.AddRange(new byte[] { 0xFE, 0x0D, 0x00, 0x08, 0xE0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 });
        }

        body.Add((byte)(extensions.Count >> 8)); body.Add((byte)extensions.Count);
        body.AddRange(extensions);

        var handshake = new List<byte> { 0x01, (byte)(body.Count >> 16), (byte)(body.Count >> 8), (byte)body.Count };
        handshake.AddRange(body);

        var record = new List<byte> { 0x16, 0x03, 0x01, (byte)(handshake.Count >> 8), (byte)handshake.Count };
        record.AddRange(handshake);
        return record.ToArray();
    }

    static async Task<(string Stdout, string Stderr, string ClientName)?> RunNodeClientAsync(
        string scriptName, string jsSource, string args, List<string> failures)
    {
        // Electron is preferred when it is installed: it is the TLS stack the live clients run, and its
        // Node side is reached with ELECTRON_RUN_AS_NODE.
        var electron = Environment.GetEnvironmentVariable("TLSMITM_ELECTRON")
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Programs", "Electron", "electron.exe");
        var node = Environment.GetEnvironmentVariable("TLSMITM_NODE");
        var useElectron = node == null && File.Exists(electron);
        var executable = node ?? (useElectron ? electron : "node");
        var clientName = useElectron ? "electron" : "node";

        var script = Path.Combine(Path.GetTempPath(), $"{scriptName}-{Environment.ProcessId}.js");
        File.WriteAllText(script, jsSource);

        var psi = new ProcessStartInfo(executable, $"\"{script}\" {args}")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        if (useElectron)
            psi.Environment["ELECTRON_RUN_AS_NODE"] = "1";

        Process process;
        try
        {
            process = Process.Start(psi)
                ?? throw new InvalidOperationException($"could not start {clientName} client");
        }
        catch (System.ComponentModel.Win32Exception)
        {
            failures.Add($"{clientName} client not found (set TLSMITM_NODE or TLSMITM_ELECTRON)");
            return null;
        }

        using (process)
        {
            var stdout = await process.StandardOutput.ReadToEndAsync();
            var stderr = await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();
            return (stdout, stderr, clientName);
        }
    }

    // The refusal has to be a property of the fixture, not of this machine: a client given a `ca` list
    // replaces the bundled roots, so no store, no Node version and no root program can make it accept.
    static async Task RunAbortClientAsync(int proxyPort, string caPemPath, List<string> notes, List<string> failures)
    {
        var js = """
            const tls = require('tls');
            const fs = require('fs');
            const port = parseInt(process.argv[2], 10);
            const ca = fs.readFileSync(process.argv[3], 'utf8');
            const s = tls.connect({ host: '127.0.0.1', port, servername: 'probe.test', ca,
                                    rejectUnauthorized: true }, () => {
              console.log(JSON.stringify({ completed: true, authorized: s.authorized }));
              s.destroy();
            });
            s.on('error', e => { console.log(JSON.stringify({ error: e.code || e.message })); process.exit(0); });
            setTimeout(() => { console.log(JSON.stringify({ error: 'timeout' })); process.exit(2); }, 12000);
            """;

        var run = await RunNodeClientAsync("abort-client", js, $"{proxyPort} \"{caPemPath}\"", failures);
        if (run == null) return;
        var (stdout, stderr, clientName) = run.Value;
        foreach (var line in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            notes.Add($"{clientName}: {line.Trim()}");

        if (stdout.Contains("\"completed\":true"))
            failures.Add($"handshake-abort: {clientName} finished a handshake its own CA list cannot verify: {stderr.Trim()}");
        else if (stdout.Contains("\"error\":\"timeout\"") || stdout.Length == 0)
            failures.Add($"handshake-abort: {clientName} neither refused nor completed: {stdout.Trim()} {stderr.Trim()}");
        else
            notes.Add($"handshake-abort: {clientName} refused the flight with {stdout.Trim()}");
    }

    static async Task CheckAbortedCaptureAsync(string[] before, int upstreamPort,
        List<string> notes, List<string> failures)
    {
        var path = await Capture.FindAsync(before,
            f => f.EndsWith("_aborted.pcap", StringComparison.Ordinal));
        if (path == null)
        {
            failures.Add("handshake-abort: the aborted client leg wrote no *_aborted.pcap");
            return;
        }

        var frames = await Capture.FramesAsync(path, upstreamPort);

        // The file opens with the writer's synthesized three-way handshake, so the TLS records start
        // after it. A capture whose first frame is a bare SYN from the client is what Wireshark needs
        // to read the file as one connection rather than a fragment out of the middle.
        var data = frames.Where(f => f.Payload.Length > 0).ToList();
        if (frames.Count == 0 || frames[0].FromServer || frames[0].Flags != 0x02
            || frames[0].Payload.Length != 0)
        {
            failures.Add("handshake-abort: the capture does not open with the client's SYN");
            return;
        }
        if (data.Count < 2)
        {
            failures.Add($"handshake-abort: capture {Path.GetFileName(path)} holds {data.Count} data frame(s), " +
                "so only one side of the handshake was recorded");
            return;
        }

        // A TLS record is content type, version, length, then the handshake message type: 0x16 0x01 is
        // a ClientHello and 0x16 0x02 the ServerHello it was answered with.
        if (data[0].FromServer || data[0].Payload.Length < 6
            || data[0].Payload[0] != 0x16 || data[0].Payload[5] != 0x01)
        {
            failures.Add("handshake-abort: the first data frame is not the client's ClientHello");
            return;
        }
        if (!System.Text.Encoding.ASCII.GetString(data[0].Payload).Contains("probe.test"))
        {
            failures.Add("handshake-abort: the recorded ClientHello carries no SNI, so it is not this session's");
            return;
        }
        var serverHello = data.FirstOrDefault(f => f.FromServer && f.Payload.Length >= 6
            && f.Payload[0] == 0x16 && f.Payload[5] == 0x02);
        if (serverHello.Payload == null)
        {
            failures.Add("handshake-abort: no ServerHello frame - the flight the client refused was not recorded");
            return;
        }

        // What the file cannot show is the certificate list itself: under TLS 1.3 everything after the
        // ServerHello is encrypted, and the capture holds the bytes the peers exchanged, not the keys.
        notes.Add($"handshake-abort: {Path.GetFileName(path)} holds the ClientHello (with SNI) and the " +
            $"{serverHello.Payload.Length}-byte flight the client refused");
    }

    static async Task RunEmsignClientAsync(int proxyPort, List<string> notes, List<string> failures)
    {
        var script = """
            const tls = require('tls');
            const port = parseInt(process.argv[2], 10);
            const host = process.argv[3] || 'probe.test';
            const defaultRoots = typeof tls.getCACertificates === 'function'
              ? tls.getCACertificates('default').length : 'unknown';
            console.log(JSON.stringify({ client: process.execPath, version: process.version, defaultRoots }));
            // rejectUnauthorized is off, and that is not a weaker test: measured on this host, a strict
            // connect that fails verification destroys the socket first, so the error handler sees
            // destroyed:true and an empty chain - the client can no longer say what it was sent. Here the
            // handshake completes, BoringSSL still reports its verdict (authorized / authorizationError,
            // same uppercase code vocabulary as the strict path's e.code), and the chain the proxy
            // actually presented is readable.
            const s = tls.connect({ host: '127.0.0.1', port, servername: host, rejectUnauthorized: false }, () => {
              const chain = [];
              let c = s.getPeerCertificate(true);
              while (c && c.subject) { chain.push(c.subject.CN); if (!c.issuerCertificate || c.issuerCertificate === c) break; c = c.issuerCertificate; }
              console.log(JSON.stringify({ authorized: s.authorized, error: s.authorizationError || null,
                                           proto: s.getProtocol(), alpn: s.alpnProtocol, depth: chain.length, chain }));
              s.write('GET / HTTP/1.1\r\nHost: ' + host + '\r\n\r\n');
            });
            let buf = '';
            s.on('data', d => { buf += d.toString(); if (buf.includes('200 OK')) { console.log(JSON.stringify({ body: 'ok' })); s.end(); process.exit(0); } });
            s.on('error', e => { console.log(JSON.stringify({ error: e.code || e.message })); process.exit(1); });
            setTimeout(() => { console.log(JSON.stringify({ error: 'timeout' })); process.exit(2); }, 12000);
            """;

        var run = await RunNodeClientAsync("emsign-client", script, $"{proxyPort} probe.test", failures);
        if (run == null) return;
        var (stdout, stderr, clientName) = run.Value;
        foreach (var line in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            notes.Add($"{clientName}: {line.Trim()}");

        // What this mode exists to prove is which chain the proxy handed a Node/Electron PID. The
        // verdict that PID's own store reaches on top of it is environment-dependent - this machine's
        // Electron accepts, a current Node reports the legacy eMSign roots as revoked - so the verdict
        // cannot carry the test: serving the Fiddler chain by mistake makes the store say "issuer not
        // found", which would otherwise read as the same expected rejection. So the presented chain is
        // checked first, and the relay has to complete either way.
        var servedEmSignChain = stdout.Contains("EM DV TLS CA") || stdout.Contains("EM OV TLS CA")
            || stdout.Contains("EM EV TLS CA");
        if (!servedEmSignChain)
        {
            failures.Add($"emsign: {clientName} was not served an emSign chain (per-PID selection or " +
                $"the chain build is broken): {stdout.Trim()} {stderr.Trim()}");
        }
        else if (!stdout.Contains("\"body\":\"ok\""))
        {
            failures.Add($"emsign: {clientName} never received the relayed body: {stdout.Trim()} {stderr.Trim()}");
        }
        else if (stdout.Contains("\"authorized\":true"))
        {
            notes.Add($"emsign: {clientName} accepted the emSign chain and the HTTP relay completed");
        }
        else if (stdout.Contains("\"error\":\"CERT_REVOKED\"") ||
                 stdout.Contains("\"error\":\"UNABLE_TO_GET_ISSUER_CERT_LOCALLY\"") ||
                 stdout.Contains("\"error\":\"UNABLE_TO_VERIFY_LEAF_SIGNATURE\""))
        {
            notes.Add($"emsign: {clientName}'s store rejects the legacy eMSign roots as expected; the chain " +
                "it was served is the emSign one and the relay completed anyway");
        }
        else
        {
            failures.Add($"{clientName} failed unexpectedly: {stdout.Trim()} {stderr.Trim()}");
        }
    }

    // Hosted Windows CI cannot add a CurrentUser\Root trust anchor without the interactive Windows
    // consent dialog. The workflow explicitly opts this harness into the disposable machine stores;
    // production RootCa keeps its real-Fiddler CurrentUser discovery unchanged, and rootcheck is the
    // mode that runs that discovery inside the CI job so the two routes are compared, not assumed.
    static X509Certificate2 LoadRootForProbe()
    {
        if (!string.Equals(Environment.GetEnvironmentVariable("TLSMITM_CI_ROOT_STORE"),
                "LocalMachine", StringComparison.OrdinalIgnoreCase))
        {
            return RootCa.GetFiddlerRoot();
        }

        const string subject = "DO_NOT_TRUST_FiddlerRoot";
        using var personal = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        personal.Open(OpenFlags.ReadOnly);
        using var roots = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        roots.Open(OpenFlags.ReadOnly);
        var machineTrusted = roots.Certificates
            .Find(X509FindType.FindBySubjectName, subject, validOnly: false)
            .Cast<X509Certificate2>()
            .Select(c => c.Thumbprint)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        // A same-subject root can be stale, so the signing test is repeated here rather than trusted
        // from the install script: the harness must never pick a key that cannot actually sign.
        var usable = personal.Certificates
            .Find(X509FindType.FindBySubjectName, subject, validOnly: false)
            .Cast<X509Certificate2>()
            .Where(c => machineTrusted.Contains(c.Thumbprint) && CanSignWith(c))
            // RootCa's ordering, minus its first key: LocalMachine\Root membership is already part of
            // the predicate above, so it is constant among these candidates.
            .OrderByDescending(c => c.NotAfter)
            .ThenBy(c => c.Thumbprint, StringComparer.Ordinal)
            .ToList();

        if (usable.Count == 0)
            throw new InvalidOperationException(
                "TLSMITM_CI_ROOT_STORE=LocalMachine but no DO_NOT_TRUST_FiddlerRoot in LocalMachine\\My " +
                "is machine-trusted with a private key that can sign");

        Console.WriteLine($"[Probe] using CI machine root {usable[0].Thumbprint} ({usable.Count} usable)");
        return usable[0];
    }

    static bool CanSignWith(X509Certificate2 cert)
    {
        try
        {
            using var key = cert.GetRSAPrivateKey();
            if (key == null) return false;
            key.SignData(new byte[4], HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    // .NET surfaces only CA= from this extension, so pathLen has to be read out of the DER:
    // SEQUENCE { [BOOLEAN ca] [INTEGER pathLen] }. The measured real root is 30 06 01 01 FF 02 01 00.
    // Returns -1 when the certificate carries no path length constraint.
    static int PathLengthOf(X509Certificate2 cert)
    {
        var der = cert.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault()?.RawData;
        if (der is null || der.Length < 4 || der[0] != 0x30 || der[1] >= 0x80) return -1;
        var i = 2;
        if (der[i] != 0x01) return -1;
        i += 2 + der[i + 1];
        if (i + 2 >= der.Length || der[i] != 0x02) return -1;
        var length = der[i + 1];
        return der[i + 1 + length];
    }

    // The suite can sign with a root the product would have to discover on its own (CI's machine store,
    // or a root the user installed by hand), so this mode calls RootCa and prints which root it returned.
    // A disagreement means every leaf in the log was signed by something the product would not use.
    static void CheckRootSelection(X509Certificate2 harnessRoot, List<string> notes, List<string> failures)
    {
        var keyUsage = harnessRoot.Extensions.OfType<X509KeyUsageExtension>()
            .Select(e => e.KeyUsages)
            .Aggregate(new X509KeyUsageFlags(), (all, flags) => all | flags);
        notes.Add($"rootcheck: signing root {harnessRoot.Thumbprint} is a CA " +
            $"{harnessRoot.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault()?.CertificateAuthority == true} " +
            $"with pathLen {PathLengthOf(harnessRoot)} (-1 means unconstrained) and keyUsage {keyUsage}");
        if (!keyUsage.HasFlag(X509KeyUsageFlags.KeyCertSign))
            failures.Add($"rootcheck: the root the leaves are signed with carries no keyCertSign bit: {keyUsage}");

        X509Certificate2? productRoot = null;
        string? enumerationFailure = null;
        try
        {
            productRoot = RootCa.GetFiddlerRoot();
        }
        catch (InvalidOperationException ex)
        {
            // Only reachable with the opt-in set: without it LoadRootForProbe *is* this call, so a
            // throw there already ended the run before any mode started.
            enumerationFailure = ex.Message;
        }

        if (productRoot == null)
        {
            notes.Add($"rootcheck: RootCa's Root/My discovery found no usable root " +
                $"({enumerationFailure}), so this job certifies the machine fixture only");
            return;
        }

        if (productRoot.Thumbprint != harnessRoot.Thumbprint)
        {
            failures.Add($"rootcheck: the product signs with {productRoot.Thumbprint} while this suite signed " +
                $"with {harnessRoot.Thumbprint} - the two routes disagree about which root is real");
            return;
        }

        notes.Add($"rootcheck: RootCa and the harness both picked {productRoot.Thumbprint}");
    }

    // The shape --init-ca has to produce, judged by the same DER the PowerShell fixture asserts: a root
    // looser than the measured Fiddler root would certify chains the real one refuses, and a root that
    // cannot sign would only fail later, on the first client handshake.
    static void CheckGeneratedRoot(List<string> notes, List<string> failures)
    {
        using var root = RootCa.CreateRootCertificate();
        var basic = root.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
        var keyUsage = root.Extensions.OfType<X509KeyUsageExtension>()
            .Select(e => e.KeyUsages)
            .Aggregate(new X509KeyUsageFlags(), (all, flags) => all | flags);
        var eku = root.Extensions.OfType<X509EnhancedKeyUsageExtension>()
            .SelectMany(e => e.EnhancedKeyUsages.Cast<Oid>())
            .Select(o => o.Value)
            .ToList();

        notes.Add($"rootcheck: --init-ca root CA={basic?.CertificateAuthority} pathLen={PathLengthOf(root)} " +
            $"keyUsage={keyUsage} eku=[{string.Join(",", eku)}]");
        if (basic is not { CertificateAuthority: true })
            failures.Add("rootcheck: --init-ca generated root does not carry basicConstraints CA=TRUE");
        var pathLen = PathLengthOf(root);
        if (pathLen != 0)
            failures.Add($"rootcheck: --init-ca generated root has pathLen {pathLen}, not 0");
        if ((keyUsage & (X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign)) !=
            (X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign))
            failures.Add($"rootcheck: --init-ca generated root keyUsage {keyUsage} lacks keyCertSign|cRLSign");
        if (!eku.Contains("1.3.6.1.5.5.7.3.1"))
            failures.Add($"rootcheck: --init-ca generated root has no serverAuth EKU ([{string.Join(",", eku)}])");

        var issued = new CertEngine(root).GetCert("probe.test");
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        if (chain.Build(issued.Leaf))
            notes.Add($"rootcheck: a leaf from the generated root ({issued.Leaf.Subject}) chains back to it");
        else
            failures.Add("rootcheck: a leaf from the generated root does not chain to it: " +
                string.Join("; ", chain.ChainStatus.Select(s => s.Status.ToString())));
    }

    // Process scoping is a decision table, so it is judged by driving it: each selector has to keep
    // the flows it names on its own key, drop the rest, and an exclusion has to win over an include.
    static void CheckProcessFilter(List<string> notes, List<string> failures)
    {
        var alice = new ClientIdentity(ClientTrust.WindowsStore, 4000, "chrome.exe [4000]", false, "chrome.exe");
        var bob = new ClientIdentity(ClientTrust.WindowsStore, 4001, "node.exe [4001]", false, "node.exe");
        var unowned = new ClientIdentity(ClientTrust.WindowsStore, 0, "unknown", false, "");

        // The redirector resolves by flow; the probe resolves by the same port so a case reads as the
        // flow it means.
        ClientIdentity Identify(IPAddress address, int port) => port switch
        {
            4000 => alice,
            4001 => bob,
            _ => unowned
        };

        var loopback = IPAddress.Loopback;
        void Expect(string what, ProcessFilter filter, int port, bool expected)
        {
            var allowed = filter.Allows(loopback, port, out var identity);
            notes.Add($"filter: {what} port {port} ({identity.Label}) -> {(allowed ? "capture" : "pass")}");
            if (allowed != expected)
                failures.Add($"filter: {what} should {(expected ? "capture" : "pass")} port {port}, " +
                    $"but it {(allowed ? "captured" : "passed")} it");
        }

        ProcessFilter Filter(int[] pids, string[] images, int[] excludedPids, string[] excludedImages) =>
            new(pids, images, excludedPids, excludedImages, Identify);

        var byPid = Filter(new[] { 4000 }, Array.Empty<string>(), Array.Empty<int>(), Array.Empty<string>());
        Expect("--pid 4000", byPid, 4000, true);
        Expect("--pid 4000", byPid, 4001, false);
        Expect("--pid 4000 (unowned)", byPid, 5000, false);

        var byImage = Filter(Array.Empty<int>(), new[] { "chrome" }, Array.Empty<int>(), Array.Empty<string>());
        Expect("--process chrome", byImage, 4000, true);
        Expect("--process chrome", byImage, 4001, false);
        Expect("--process chrome (unowned)", byImage, 5000, false);

        var excludePid = Filter(Array.Empty<int>(), Array.Empty<string>(), new[] { 4000 }, Array.Empty<string>());
        Expect("--exclude-pid 4000", excludePid, 4000, false);
        Expect("--exclude-pid 4000", excludePid, 4001, true);
        Expect("--exclude-pid 4000 (unowned)", excludePid, 5000, true);

        var excludeImage = Filter(Array.Empty<int>(), Array.Empty<string>(), Array.Empty<int>(), new[] { "chrome" });
        Expect("--exclude-process chrome", excludeImage, 4000, false);
        Expect("--exclude-process chrome", excludeImage, 4001, true);
        Expect("--exclude-process chrome (unowned)", excludeImage, 5000, true);
        Expect("--exclude-process Chrome.exe", Filter(
            Array.Empty<int>(), Array.Empty<string>(), Array.Empty<int>(), new[] { "Chrome.exe" }), 4000, false);

        // Either include key can name a flow: the two lists are one whitelist, not an intersection.
        var includeBoth = Filter(new[] { 4000 }, new[] { "node" }, Array.Empty<int>(), Array.Empty<string>());
        Expect("--pid 4000 --process node", includeBoth, 4000, true);
        Expect("--pid 4000 --process node", includeBoth, 4001, true);
        Expect("--pid 4000 --process node (unowned)", includeBoth, 5000, false);

        // An exclusion wins over an include even when the two name the process through different keys:
        // "capture chrome but not pid 4000" must not capture pid 4000.
        var crossKeys = Filter(new[] { 4000 }, new[] { "chrome" }, new[] { 4000 }, Array.Empty<string>());
        Expect("--pid 4000 --process chrome --exclude-pid 4000", crossKeys, 4000, false);
        Expect("--pid 4000 --process chrome --exclude-pid 4000", crossKeys, 4001, false);

        var otherKey = Filter(new[] { 4000 }, Array.Empty<string>(), new[] { 4001 }, new[] { "node" });
        Expect("--pid 4000 --exclude-pid 4001 --exclude-process node", otherKey, 4000, true);
        Expect("--pid 4000 --exclude-pid 4001 --exclude-process node", otherKey, 4001, false);

        // Rule 3 of ProcessFilter: an inactive filter never consults the table at all, so a machine with
        // no scoping flags behaves exactly as before and cannot lose a flow to a lookup failure.
        var looked = 0;
        var inactive = new ProcessFilter(Array.Empty<int>(), Array.Empty<string>(),
            Array.Empty<int>(), Array.Empty<string>(), (_, _) =>
        {
            looked++;
            return unowned;
        });
        if (!inactive.IsActive)
            notes.Add("filter: no flags -> inactive");
        else
            failures.Add("filter: a filter with no pids and no exclusions reported itself active");
        Expect("no flags", inactive, 5000, true);
        if (looked != 0)
            failures.Add($"filter: an inactive filter ran {looked} process lookups");
    }
}

// Hands the reader the first N TLS records and discards whatever the peer put behind them, which is the
// shape a refusal has to be offered in: the record header is in the clear even when the early payload is
// not, so where the hello ends is knowable without reading what follows it. N = 0 hands on nothing at all.
sealed class FirstRecordStream : Stream
{
    private readonly Stream _inner;
    private readonly int _recordsToServe;
    private readonly MemoryStream _handed = new();
    private int _collected;
    private int _offset;

    public FirstRecordStream(Stream inner, int recordsToServe)
    {
        _inner = inner;
        _recordsToServe = recordsToServe;
    }

    public override bool CanRead => _inner.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => _inner.CanWrite;
    public override long Length => _inner.Length;
    public override long Position { get => _inner.Position; set => _inner.Position = value; }
    public override void Flush() => _inner.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        => _inner.WriteAsync(buffer, cancellationToken);

    public override int Read(byte[] buffer, int offset, int count)
        => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        while (_offset >= _handed.Length && _collected < _recordsToServe)
        {
            var record = new byte[5];
            var got = await ReadFullAsync(record, cancellationToken);
            if (got == 0) return 0;
            if (got < record.Length) throw new IOException("the peer closed inside a record header");
            var body = (record[3] << 8) | record[4];
            Array.Resize(ref record, 5 + body);
            if (await ReadFullAsync(record.AsMemory(5), cancellationToken) != body)
                throw new IOException("the peer closed inside a record");
            _handed.Write(record, 0, record.Length);
            _collected++;
        }

        if (_offset < _handed.Length)
        {
            var n = (int)Math.Min(buffer.Length, _handed.Length - _offset);
            _handed.GetBuffer().AsSpan(_offset, n).CopyTo(buffer.Span);
            _offset += n;
            return n;
        }

        var scratch = new byte[4096];
        while (true)
        {
            var read = await _inner.ReadAsync(scratch, cancellationToken);
            if (read == 0) return 0;
        }
    }

    private async Task<int> ReadFullAsync(Memory<byte> target, CancellationToken cancellationToken)
    {
        var total = 0;
        while (total < target.Length)
        {
            var read = await _inner.ReadAsync(target[total..], cancellationToken);
            if (read == 0) break;
            total += read;
        }
        return total;
    }
}

sealed class FakeRedirector : IRedirector
{
    private readonly Func<int, IPEndPoint> _targetFor;
    private int _lookupIndex;
    private int _claims;
    private int _releases;

    public FakeRedirector(Func<int, IPEndPoint> targetFor) => _targetFor = targetFor;

    public int Claims => Volatile.Read(ref _claims);
    public int Releases => Volatile.Read(ref _releases);

    // Connections are handed their original destination in arrival order: control first, then the
    // data channel it opens later, which is the only way the harness can model an ephemeral port.
    // Nothing was rewritten here, so the socket's own endpoints are the client's and go back as such.
    public OriginalDest? LookupOriginalDest(IPAddress deliveredTo, int token, IPAddress serverAddr)
    {
        var target = _targetFor(Interlocked.Increment(ref _lookupIndex) - 1);
        Interlocked.Increment(ref _claims);
        return new OriginalDest(target.Address, target.Port, deliveredTo, token);
    }

    // No token pool here, so nothing is given back to; the count is what the run is judged on.
    public void ReleaseFlow(int token) => Interlocked.Increment(ref _releases);

    public void RegisterExemption(int sourcePort) { }

    public void UnregisterExemption(int sourcePort) { }

    public void RegisterFlowExemption(int sourcePort, IPAddress destination, int destinationPort) { }

    public void UnregisterFlowExemption(int sourcePort, IPAddress destination, int destinationPort) { }

    public void RegisterLocalService(int dstPort) { }
}

// --- the scripted media dialogues -----------------------------------------------------------------
//
// A media mode drives both ends of its session from one script, so the octets the harness's client writes
// and the octets the fake upstream expects cannot drift apart. Each turn names the framing rule its reader
// uses to find the message's end, because that is the whole question for a relay: for RTSP and SIP an empty
// line ends only the headers, and the body is the octet count Content-Length declares (RFC 7826 §5.4 and
// §18.17, RFC 3261 §7.5); an RTSP interleaved block puts no delimiter between its four-octet header and its
// payload (RFC 7826 §14); a SIP keep-alive is a bare CRLF pair that is an exchange in itself (RFC 5626
// §4.4.1); and an RTMP message declares its length in its own header and is then cut again by the chunk
// size. A turn also says whether its octets are one write or several, because a real server sends a header
// block and then a body and a real client does not keep its messages inside one buffer.
enum MediaRead
{
    Text,     // start-line, headers to the empty line, then the Content-Length octets
    Frame,    // RTSP's interleaved block: '$', channel, two-octet length, payload
    Exact,    // a fixed octet count, for the octets that declare no length at all
    Chunks    // RTMP's chunk framing, reassembled by the message's declared length
}

sealed record RtmpMessage(int Csid, byte Type, uint Timestamp, uint StreamId, byte[] Body);

sealed record MediaTurn(string Label, bool FromClient, byte[] Bytes, MediaRead Shape,
    int[]? Splits = null, RtmpMessage[]? Decoded = null)
{
    public static MediaTurn Text(string label, bool fromClient, string message, params int[] splits) =>
        new(label, fromClient, Encoding.ASCII.GetBytes(message), MediaRead.Text, Split(splits));

    public static MediaTurn Block(string label, bool fromClient, byte channel, byte[] payload,
        params int[] splits) =>
        new(label, fromClient, Media.InterleavedFrame(channel, payload), MediaRead.Frame, Split(splits));

    public static MediaTurn Octets(string label, bool fromClient, byte[] bytes, params int[] splits) =>
        new(label, fromClient, bytes, MediaRead.Exact, Split(splits));

    public static MediaTurn Chunks(string label, bool fromClient, int chunkSize, int[]? splits,
        params RtmpMessage[] messages) =>
        new(label, fromClient, Media.RtmpWire(chunkSize, messages), MediaRead.Chunks, splits, messages);

    static int[]? Split(int[] splits) => splits.Length == 0 ? null : splits;
}

static class Media
{
    // RFC 7826 §14: "Stream data, such as RTP packets, is encapsulated by an ASCII dollar sign (36 decimal)
    // followed by a one-octet channel identifier and the length of the encapsulated binary data as a binary,
    // two-octet unsigned integer in network octet order", and "The stream data follows immediately
    // afterwards, without a CRLF". The payload is shaped like an RTP header and carries a CRLF pair inside
    // it, so a relay that looked for a message boundary would corrupt the block rather than pass it.
    public static byte[] InterleavedFrame(byte channel, byte[] payload)
    {
        var frame = new byte[4 + payload.Length];
        frame[0] = 0x24;
        frame[1] = channel;
        frame[2] = (byte)(payload.Length >> 8);
        frame[3] = (byte)payload.Length;
        payload.CopyTo(frame, 4);
        return frame;
    }

    public static byte[] InterleavedPayload(int sequence) => new byte[]
    {
        0x80, 0x20, (byte)(sequence >> 8), (byte)sequence, 0x00, 0x00, 0x00, 0x2a,
        0x0d, 0x0a, 0x0d, 0x0a, 0x80, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    // Measured 2026-11-03 from a media client's own bytes on a raw socket: the first flight on an rtmp://
    // connection is 1537 octets - 0x03, a four-octet timestamp, four zero octets and 1528 arbitrary ones -
    // and on rtmps:// the same octets arrive after the ClientHello. Nothing there has a line structure, so
    // the fixture plants a CRLF pair in the filler: that is what a relay which waited for a blank line
    // before forwarding would stop on. The 1536-octet form is a block with no version byte in front of it,
    // which is what C2 and S2 both are - the client sends its after the server's S0+S1, the server sends
    // its after the client's C2.
    public static byte[] BuildRtmpFlight(byte fill, bool withVersion)
    {
        var flight = new byte[withVersion ? 1537 : 1536];
        var body = new Span<byte>(flight, withVersion ? 1 : 0, 1536);
        body[3] = 0x2c;
        for (var i = 8; i < body.Length; i++) body[i] = (byte)(i + fill);
        body[600] = 0x0d; body[601] = 0x0a; body[602] = 0x0d; body[603] = 0x0a;
        if (withVersion) flight[0] = 0x03;
        return flight;
    }

    // Reads a fixed number of octets, or whatever arrived before the window closed or the peer stopped.
    // The shortfall is a verdict the caller makes, not an exception here: a flight that never completed is
    // exactly what a relay that withheld part of it looks like from the far end.
    public static async Task<byte[]> ReadUpTo(Stream s, int length, TimeSpan limit)
    {
        var buffer = new byte[length];
        var got = 0;
        using var cts = new CancellationTokenSource(limit);
        try
        {
            while (got < length)
            {
                var n = await s.ReadAsync(buffer.AsMemory(got), cts.Token);
                if (n == 0) break;
                got += n;
            }
        }
        catch (OperationCanceledException) { }
        return buffer[..got];
    }

    public static int FirstDifference(byte[] arrived, byte[] sent)
    {
        var shared = Math.Min(arrived.Length, sent.Length);
        for (var i = 0; i < shared; i++) if (arrived[i] != sent[i]) return i;
        return shared;
    }

    // The octet count is computed here, so a body and the length its own headers declare cannot disagree.
    // RFC 7826 §18.17: "Unlike HTTP, it MUST be included in all messages that carry a message body beyond
    // the header portion of the RTSP message. If it is missing, a default value of zero is assumed."
    public static string Message(string startLine, string[] headers, string body,
        string lengthHeader = "Content-Length")
    {
        var sb = new StringBuilder(startLine).Append("\r\n");
        foreach (var header in headers) sb.Append(header).Append("\r\n");
        return sb.Append(lengthHeader).Append(": ").Append(Encoding.ASCII.GetByteCount(body))
            .Append("\r\n\r\n").Append(body).ToString();
    }

    // Where the body begins, which is the offset a real server puts a write boundary at.
    public static int BodyAt(string message) =>
        message.IndexOf("\r\n\r\n", StringComparison.Ordinal) + 4;

    // The control plane of RFC 7826: DESCRIBE answers with SDP, SETUP is answered with the channels the
    // server actually chose, and media then arrives on those. §18.54: "The channel number given in the
    // request is only a guidance from the client to the server on what channel number(s) to use. The server
    // MAY set any valid channel number in the response. The declared channels are bidirectional, so both end
    // parties MAY send data on the given channel." The request asks for 0-1 and the answer is 5-6, which is
    // the RFC's own example (§14), so the blocks that follow are only correct if the reader took the answer
    // and not the request. §14 adds that RTCP "MUST be sent on the first available channel that is higher
    // than the RTP channel", hence channel 6. The keep-alive is §13.8's: GET_PARAMETER "can also be used
    // without a message body or any header that requests parameters for keep-alive purposes".
    public static List<MediaTurn> RtspScript()
    {
        const string uri = "rtsp://probe.test:322/media";
        // The body ends in a CRLF pair of its own, so the message holds a blank line that is not its end -
        // §5.4 puts the length of the body in Content-Length and §9.2 leaves no transfer coding that could
        // say anything else.
        var sdp = "v=0\r\no=probe 1 1 IN IP4 127.0.0.1\r\ns=Rtsps fixture\r\nt=0 0\r\n" +
                  "m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=control:trackID=1\r\n\r\n";
        var describe = Message("RTSP/2.0 200 OK",
            new[] { "CSeq: 2", "Content-Type: application/sdp", $"Content-Base: {uri}/" }, sdp);

        return
        [
            MediaTurn.Text("OPTIONS", true,
                Message($"OPTIONS {uri} RTSP/2.0", new[] { "CSeq: 1", "User-Agent: probe" }, "")),
            MediaTurn.Text("200 to OPTIONS", false,
                Message("RTSP/2.0 200 OK", new[]
                {
                    "CSeq: 1", "Public: OPTIONS, DESCRIBE, SETUP, PLAY, GET_PARAMETER, TEARDOWN"
                }, "")),
            MediaTurn.Text("DESCRIBE", true,
                Message($"DESCRIBE {uri} RTSP/2.0", new[] { "CSeq: 2", "Accept: application/sdp" }, "")),
            MediaTurn.Text("200 with the SDP body, headers and body as two writes", false, describe,
                BodyAt(describe)),
            MediaTurn.Text("SETUP asks for channels 0-1", true,
                Message($"SETUP {uri}/trackID=1 RTSP/2.0",
                    new[] { "CSeq: 3", "Transport: RTP/AVP/TCP;unicast;interleaved=0-1" }, "")),
            MediaTurn.Text("200 answers channels 5-6 and the session", false,
                Message("RTSP/2.0 200 OK", new[]
                {
                    "CSeq: 3", "Transport: RTP/AVP/TCP;unicast;interleaved=5-6",
                    "Session: 12345678;timeout=60"
                }, "")),
            MediaTurn.Text("PLAY", true,
                Message($"PLAY {uri} RTSP/2.0",
                    new[] { "CSeq: 4", "Session: 12345678", "Range: npt=0.000-" }, "")),
            MediaTurn.Text("200 with RTP-Info", false,
                Message("RTSP/2.0 200 OK", new[]
                {
                    "CSeq: 4", "Session: 12345678", $"RTP-Info: url={uri}/trackID=1;seq=42;rtptime=1234"
                }, "")),
            MediaTurn.Block("RTP on channel 5, block header and payload as two writes", false, 5,
                InterleavedPayload(1), 4),
            MediaTurn.Block("RTCP on channel 6", false, 6, InterleavedPayload(2)),
            MediaTurn.Block("the client's RTCP on channel 6", true, 6, InterleavedPayload(3)),
            MediaTurn.Block("the client's RTP on channel 5", true, 5, InterleavedPayload(4)),
            MediaTurn.Text("GET_PARAMETER keep-alive between media blocks", true,
                Message($"GET_PARAMETER {uri} RTSP/2.0", new[] { "CSeq: 5", "Session: 12345678" }, "")),
            MediaTurn.Text("200 to the keep-alive", false,
                Message("RTSP/2.0 200 OK", new[] { "CSeq: 5", "Session: 12345678" }, "")),
            MediaTurn.Block("RTP on channel 5 after the text exchange", false, 5, InterleavedPayload(5)),
            MediaTurn.Text("TEARDOWN", true,
                Message($"TEARDOWN {uri} RTSP/2.0", new[] { "CSeq: 6", "Session: 12345678" }, "")),
            MediaTurn.Text("200 to TEARDOWN", false, Message("RTSP/2.0 200 OK", new[] { "CSeq: 6" }, "")),
        ];
    }

    // RFC 3261 over TLS (§5 Table 1 note (1): "5061 for sip: using TLS over TCP and sips: over TCP"). Every
    // request carries Max-Forwards (§8.1.1.6: "A UAC MUST insert a Max-Forwards header field into each
    // request it originates with a value that SHOULD be 70") and a Via branch that is unique for each
    // request (§7.3.3.1: "The branch parameter value MUST be unique across space and time for all requests
    // sent by the UA"). The REGISTER body is two CRLF pairs, so only its Content-Length keeps it from being
    // read as an empty line ending the message. The INVITE's 100 and 180 are provisional and the 200 is the
    // final answer (§21.1.1, §21.1.2), the ACK repeats the original request's Call-ID, From, top Via and
    // CSeq number and takes the To from the response it acknowledges (§17.1.1.3), and the 200's own
    // content-length is spelled in lower case because "When comparing header fields, field names are always
    // case-insensitive" (§7.3.1). Finally RFC 5626 §4.4.1: the client's "ping" is a double CRLF and the
    // server's "pong" a single one, they "need to be sent between SIP messages and cannot be sent in the
    // middle of a SIP message", and "If sending over TLS, the CRLFs are sent inside the TLS protected
    // channel".
    public static List<MediaTurn> SipScript()
    {
        const string callId = "probe-call-1@127.0.0.1";
        const string from = "From: <sips:alice@probe.test>;tag=cli-1";
        const string toRegister = "To: <sips:alice@probe.test>";
        const string toInvite = "To: <sips:bob@probe.test>";
        const string toAnswered = "To: <sips:bob@probe.test>;tag=srv-1";
        var sdp = "v=0\r\no=alice 1 1 IN IP4 127.0.0.1\r\ns=Sips fixture\r\nt=0 0\r\n" +
                  "m=audio 49170 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
        string Via(int branch) => $"Via: SIP/2.0/TLS 127.0.0.1:5061;branch=z9hG4bK-probe{branch}";

        var invite = Message("INVITE sips:bob@probe.test SIP/2.0", new[]
        {
            Via(3), from, toInvite, $"Call-ID: {callId}", "CSeq: 6 INVITE", "Max-Forwards: 70",
            "Contact: <sips:alice@127.0.0.1:5061>", "Content-Type: application/sdp",
            "Allow: INVITE, ACK, BYE, CANCEL, OPTIONS"
        }, sdp);
        var answered = Message("SIP/2.0 200 OK", new[]
        {
            Via(3), from, toAnswered, $"Call-ID: {callId}", "CSeq: 6 INVITE",
            "Contact: <sips:bob@127.0.0.1:5061>", "Content-Type: application/sdp"
        }, sdp, "content-length");

        return
        [
            MediaTurn.Text("REGISTER whose body is two CRLF pairs", true,
                Message("REGISTER sips:probe.test SIP/2.0", new[]
                {
                    Via(1), from, toRegister, $"Call-ID: {callId}", "CSeq: 1 REGISTER",
                    "Max-Forwards: 70", "Contact: <sips:alice@127.0.0.1:5061>"
                }, "\r\n\r\n\r\n\r\n")),
            MediaTurn.Text("100 Trying", false,
                Message("SIP/2.0 100 Trying",
                    new[] { Via(1), from, toRegister, $"Call-ID: {callId}", "CSeq: 1 REGISTER" }, "")),
            MediaTurn.Text("200 OK to REGISTER", false,
                Message("SIP/2.0 200 OK", new[]
                {
                    Via(1), from, toRegister, $"Call-ID: {callId}", "CSeq: 1 REGISTER",
                    "Contact: <sips:alice@127.0.0.1:5061>;expires=3600"
                }, "")),
            MediaTurn.Text("INVITE with SDP, one write ending inside the body", true, invite,
                BodyAt(invite) + 20),
            MediaTurn.Text("180 Ringing", false,
                Message("SIP/2.0 180 Ringing", new[]
                {
                    Via(3), from, toInvite, $"Call-ID: {callId}", "CSeq: 6 INVITE",
                    "Contact: <sips:bob@127.0.0.1:5061>"
                }, "")),
            MediaTurn.Text("200 OK with SDP, headers and body as two writes", false, answered,
                BodyAt(answered)),
            MediaTurn.Text("ACK as 17.1.1.3 requires", true,
                Message("ACK sips:bob@probe.test SIP/2.0", new[]
                {
                    Via(3), from, toAnswered, $"Call-ID: {callId}", "CSeq: 6 INVITE", "Max-Forwards: 70",
                    "Content-Type: application/sdp"
                }, "")),
            MediaTurn.Octets("keep-alive ping: double CRLF", true, new byte[] { 0x0d, 0x0a, 0x0d, 0x0a }),
            MediaTurn.Octets("keep-alive pong: single CRLF", false, new byte[] { 0x0d, 0x0a }),
            MediaTurn.Text("BYE", true,
                Message("BYE sips:bob@probe.test SIP/2.0", new[]
                {
                    Via(4), from, toAnswered, $"Call-ID: {callId}", "CSeq: 7 BYE", "Max-Forwards: 70",
                    "Reason: Q854;cause=16;text=\"Normal clearing\""
                }, "")),
            MediaTurn.Text("200 OK to BYE", false,
                Message("SIP/2.0 200 OK",
                    new[] { Via(4), from, toAnswered, $"Call-ID: {callId}", "CSeq: 7 BYE" }, "")),
        ];
    }

    // RTMP's chunk framing is a vendor's specification, so every number this script writes was read back
    // from the fixture's own decrypted capture with a packet dissector (measured 2026-11-03, Wireshark's
    // Real Time Messaging Protocol dissector over the rtmps mode's pcap): the one-octet basic header's high
    // two bits are the format and the low six the chunk stream id; format 0 adds a 24-bit timestamp, a
    // 24-bit message length, a one-octet message type and a 32-bit little-endian message stream id; a
    // timestamp field of 0xFFFFFF is followed by a 32-bit one; and the body is dealt out in pieces of at
    // most the chunk size, each later piece repeating only the basic header. Message type 1 is Set Chunk
    // Size, which the reader has to adopt before it can slice anything after it. Type 20 is an AMF0 command
    // and 8 an audio message.
    public const byte RtmpSetChunkSize = 1;
    public const byte RtmpAudio = 8;
    public const byte RtmpCommand = 20;
    public const uint RtmpExtendedTimestamp = 0xFFFFFF;
    private const int RtmpDefaultChunkSize = 128;

    // The handshake's four blocks come in this order and in no other (measured 2026-11-03: a session that
    // sent only the first three had the following 1536 octets of the server's chunk stream taken for the
    // fourth block, and every chunk header after that was dissected garbled).
    public static List<MediaTurn> RtmpScript()
    {
        var connectBody = Amf(
            AmfString("connect"),
            AmfNumber(1),
            AmfObject(
                ("app", AmfString("live")),
                ("flashVer", AmfString("FMP/6,0,0,0")),
                ("tcUrl", AmfString("rtmps://probe.test/live")),
                ("fp", AmfString("Adobe fmp 6,0,0,0")),
                ("audioCodecs", AmfNumber(4071)),
                ("videoCodecs", AmfNumber(252)),
                ("videoFunction", AmfNumber(1)),
                ("pageUrl", AmfString("https://probe.test/player")),
                ("swfUrl", AmfString("https://probe.test/player.swf"))));
        var clientAudio = RtmpAudioBody(300);
        var serverAudio = RtmpAudioBody(5000);

        return
        [
            MediaTurn.Octets("C0+C1, 1537 octets with nothing a reader could stop on", true,
                BuildRtmpFlight(0x11, true)),
            MediaTurn.Octets("S0+S1", false, BuildRtmpFlight(0x22, true)),
            MediaTurn.Octets("C2", true, BuildRtmpFlight(0x33, false)),
            MediaTurn.Octets("S2, the block that closes the handshake", false, BuildRtmpFlight(0x44, false)),
            MediaTurn.Chunks("connect at the default chunk size, so two chunks written in three pieces",
                true, RtmpDefaultChunkSize,
                new[] { 13, 12 + RtmpDefaultChunkSize },
                new RtmpMessage(3, RtmpCommand, 0, 0, connectBody)),
            MediaTurn.Chunks("the client raises its chunk size to 4096", true, RtmpDefaultChunkSize, null,
                new RtmpMessage(2, RtmpSetChunkSize, 0, 0, new byte[] { 0x00, 0x00, 0x10, 0x00 })),
            MediaTurn.Chunks("the server raises its chunk size to 4096", false, RtmpDefaultChunkSize, null,
                new RtmpMessage(2, RtmpSetChunkSize, 0, 0, new byte[] { 0x00, 0x00, 0x10, 0x00 })),
            MediaTurn.Chunks("_result for connect", false, 4096, null,
                new RtmpMessage(3, RtmpCommand, 0, 0, Amf(
                    AmfString("_result"), AmfNumber(1),
                    AmfObject(("fmsVer", AmfString("FMS/3,5,3,888")), ("capabilities", AmfNumber(31))),
                    AmfObject(
                        ("level", AmfString("status")),
                        ("code", AmfString("NetConnection.Connect.Success")),
                        ("description", AmfString("Connection succeeded.")),
                        ("objectEncoding", AmfNumber(0)))))),
            MediaTurn.Chunks("createStream", true, 4096, null,
                new RtmpMessage(3, RtmpCommand, 0, 0,
                    Amf(AmfString("createStream"), AmfNumber(2), AmfNull()))),
            MediaTurn.Chunks("_result naming stream 1", false, 4096, null,
                new RtmpMessage(3, RtmpCommand, 0, 0,
                    Amf(AmfString("_result"), AmfNumber(2), AmfNull(), AmfNumber(1)))),
            MediaTurn.Chunks("publish, with a timestamp past the 24-bit field", true, 4096, null,
                new RtmpMessage(4, RtmpCommand, RtmpExtendedTimestamp + 1, 1,
                    Amf(AmfString("publish"), AmfNumber(3), AmfNull(), AmfString("stream-name")))),
            MediaTurn.Chunks("onStatus", false, 4096, null,
                new RtmpMessage(5, RtmpCommand, 0, 1, Amf(
                    AmfString("onStatus"), AmfNumber(0), AmfNull(),
                    AmfObject(
                        ("level", AmfString("status")),
                        ("code", AmfString("NetStream.Publish.Start")),
                        ("description", AmfString("Start publishing")))))),
            MediaTurn.Chunks("audio from the client", true, 4096, new[] { 20 },
                new RtmpMessage(6, RtmpAudio, 40, 1, clientAudio)),
            MediaTurn.Chunks("5000 octets of audio from the server, across two chunks in three pieces",
                false, 4096, new[] { 12 + 4096, 12 + 4096 + 400 },
                new RtmpMessage(6, RtmpAudio, 0, 1, serverAudio)),
        ];
    }

    // An audio message body: two-octet sound header then filler that holds a CRLF pair, so a reader that
    // wanted a line ending inside the body would find one that means nothing.
    static byte[] RtmpAudioBody(int length)
    {
        var body = new byte[length];
        body[0] = 0xaf; body[1] = 0x00; body[2] = 0x00; body[3] = 0x00; body[4] = 0x00;
        for (var i = 5; i < length; i++) body[i] = (byte)i;
        if (length > 120) { body[100] = 0x0d; body[101] = 0x0a; body[102] = 0x0d; body[103] = 0x0a; }
        return body;
    }

    static byte[] Amf(params byte[][] parts)
    {
        var all = new MemoryStream();
        foreach (var part in parts) all.Write(part);
        return all.ToArray();
    }

    static byte[] AmfString(string value)
    {
        var text = Encoding.UTF8.GetBytes(value);
        var outBytes = new byte[3 + text.Length];
        outBytes[0] = 0x02;
        outBytes[1] = (byte)(text.Length >> 8);
        outBytes[2] = (byte)text.Length;
        text.CopyTo(outBytes, 3);
        return outBytes;
    }

    static byte[] AmfNumber(double value)
    {
        var bytes = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
        return new byte[] { 0x00 }.Concat(bytes).ToArray();
    }

    // The mirror of AmfString, for reading a message this harness did not write: an AMF0 string is its
    // marker, a 16-bit big-endian length and then the octets, and a command body opens with the method name.
    public static string? AmfMethod(byte[] body)
    {
        if (body.Length < 3 || body[0] != 0x02) return null;
        var length = body[1] << 8 | body[2];
        return body.Length < 3 + length ? null : Encoding.UTF8.GetString(body, 3, length);
    }

    static byte[] AmfNull() => [0x05];

    static byte[] AmfObject(params (string Key, byte[] Value)[] entries)
    {
        var body = new MemoryStream();
        body.WriteByte(0x03);
        foreach (var (key, value) in entries)
        {
            var text = Encoding.UTF8.GetBytes(key);
            body.WriteByte((byte)(text.Length >> 8));
            body.WriteByte((byte)text.Length);
            body.Write(text);
            body.Write(value);
        }
        body.Write(new byte[] { 0x00, 0x00, 0x09 });
        return body.ToArray();
    }

    public static byte[] RtmpWire(int chunkSize, params RtmpMessage[] messages)
    {
        var wire = new MemoryStream();
        foreach (var message in messages)
        {
            var extended = message.Timestamp >= RtmpExtendedTimestamp;
            var stamp = extended ? RtmpExtendedTimestamp : message.Timestamp;
            var offset = 0;
            do
            {
                var piece = Math.Min(chunkSize, message.Body.Length - offset);
                wire.WriteByte((byte)(((offset == 0 ? 0 : 3) << 6) | message.Csid));
                if (offset == 0)
                {
                    WriteBe24(wire, stamp);
                    WriteBe24(wire, (uint)message.Body.Length);
                    wire.WriteByte(message.Type);
                    WriteLe32(wire, message.StreamId);
                }
                if (extended) WriteBe32(wire, message.Timestamp);
                wire.Write(message.Body, offset, piece);
                offset += piece;
            }
            while (offset < message.Body.Length);
        }
        return wire.ToArray();
    }

    static void WriteBe24(Stream s, uint value)
    {
        s.WriteByte((byte)(value >> 16));
        s.WriteByte((byte)(value >> 8));
        s.WriteByte((byte)value);
    }

    static void WriteBe32(Stream s, uint value)
    {
        s.WriteByte((byte)(value >> 24));
        s.WriteByte((byte)(value >> 16));
        s.WriteByte((byte)(value >> 8));
        s.WriteByte((byte)value);
    }

    static void WriteLe32(Stream s, uint value)
    {
        s.WriteByte((byte)value);
        s.WriteByte((byte)(value >> 8));
        s.WriteByte((byte)(value >> 16));
        s.WriteByte((byte)(value >> 24));
    }

    public static uint Be24(byte[] bytes, int at) => (uint)((bytes[at] << 16) | (bytes[at + 1] << 8) | bytes[at + 2]);
    public static uint Be32(byte[] bytes) => (uint)((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]);
    public static uint Le32(byte[] bytes, int at = 0) =>
        (uint)(bytes[at] | (bytes[at + 1] << 8) | (bytes[at + 2] << 16) | (bytes[at + 3] << 24));

    static async Task<byte> ReadOctet(Stream s)
    {
        var one = new byte[1];
        await s.ReadExactlyAsync(one);
        return one[0];
    }

    public static async Task<byte[]> ReadOctets(Stream s, int count)
    {
        var buffer = new byte[count];
        await s.ReadExactlyAsync(buffer);
        return buffer;
    }

    // The reader stops where the dialect says the message stops, not where a write happened to end: empty
    // lines before a start-line are ignored (RFC 7826 §5.1, and RFC 3261 §7.5 puts the same duty on SIP),
    // the header block ends at the empty line, and the body is then the declared number of octets whatever
    // it contains. Content-Length is matched without regard to case (RFC 3261 §7.3.1) and assumed zero when
    // it is missing (RFC 7826 §18.17).
    static async Task<byte[]> ReadTextMessage(Stream s)
    {
        var message = new MemoryStream();
        var line = new StringBuilder();
        var sawStartLine = false;
        var bodyLength = 0;
        while (true)
        {
            var b = await ReadOctet(s);
            message.WriteByte(b);
            if (b != (byte)'\n')
            {
                if (b != (byte)'\r') line.Append((char)b);
                continue;
            }

            var text = line.ToString();
            line.Clear();
            if (text.Length == 0)
            {
                if (!sawStartLine)
                {
                    message.SetLength(0);
                    continue;
                }
                break;
            }

            sawStartLine = true;
            var colon = text.IndexOf(':');
            if (colon <= 0 ||
                !text.Substring(0, colon).Trim().Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                continue;
            if (int.TryParse(text.Substring(colon + 1).Trim(), out var declared)) bodyLength = declared;
        }

        if (bodyLength > 0) message.Write(await ReadOctets(s, bodyLength));
        return message.ToArray();
    }

    // RFC 7826 §14 makes the length field the only thing that says where a block ends, so the reader takes
    // it on faith and then that many octets - which is also what survives a relay that re-chunked the file.
    static async Task<byte[]> ReadFrame(Stream s)
    {
        var head = await ReadOctets(s, 4);
        var payload = await ReadOctets(s, (head[2] << 8) | head[3]);
        return head.Concat(payload).ToArray();
    }

    // One turn of the script, either way. A write boundary is a property of the fixture's own discipline,
    // so a boundary that is not inside the message is a script bug and says so rather than quietly sending
    // the turn as one write.
    static async Task WriteTurn(Stream ssl, MediaTurn turn)
    {
        var at = 0;
        foreach (var split in turn.Splits ?? Array.Empty<int>())
        {
            if (split <= at || split >= turn.Bytes.Length)
                throw new InvalidOperationException($"turn '{turn.Label}' names a write boundary at {split}, " +
                                                   $"which is not inside it past {at}");
            await ssl.WriteAsync(turn.Bytes.AsMemory(at, split - at));
            await ssl.FlushAsync();
            at = split;
        }
        await ssl.WriteAsync(turn.Bytes.AsMemory(at));
        await ssl.FlushAsync();
    }

    static async Task ReadTurn(Stream ssl, MediaTurn turn, RtmpChunks inbound, string label,
        List<string> failures)
    {
        if (turn.Shape == MediaRead.Chunks)
        {
            var (wire, messages) = await inbound.ReadUntil(turn.Bytes.Length);
            if (!wire.AsSpan().SequenceEqual(turn.Bytes))
            {
                failures.Add($"{label}: turn '{turn.Label}' arrived as {wire.Length} octets with the first " +
                             $"difference at {FirstDifference(wire, turn.Bytes)}, not the " +
                             $"{turn.Bytes.Length} sent");
                return;
            }
            var mismatch = RtmpDifference(messages, turn.Decoded!);
            if (mismatch != null)
                failures.Add($"{label}: turn '{turn.Label}' unframed as {mismatch} from {wire.Length} wire " +
                            $"octets opening {Convert.ToHexString(wire[..Math.Min(wire.Length, 24)])}");
            return;
        }

        var arrived = turn.Shape switch
        {
            MediaRead.Text => await ReadTextMessage(ssl),
            MediaRead.Frame => await ReadFrame(ssl),
            _ => await ReadOctets(ssl, turn.Bytes.Length)
        };
        if (!arrived.AsSpan().SequenceEqual(turn.Bytes))
            failures.Add($"{label}: turn '{turn.Label}' arrived as {arrived.Length} octets with the first " +
                         $"difference at {FirstDifference(arrived, turn.Bytes)}, not the " +
                         $"{turn.Bytes.Length} sent");
    }

    static string? RtmpDifference(List<RtmpMessage> arrived, RtmpMessage[] sent)
    {
        if (arrived.Count != sent.Length)
            return $"{arrived.Count} message(s) [{string.Join("; ", arrived.Select(Describe))}] instead of " +
                   $"{sent.Length} [{string.Join("; ", sent.Select(Describe))}]";
        for (var i = 0; i < arrived.Count; i++)
        {
            if (arrived[i].Csid != sent[i].Csid || arrived[i].Type != sent[i].Type ||
                arrived[i].Timestamp != sent[i].Timestamp || arrived[i].StreamId != sent[i].StreamId ||
                !arrived[i].Body.AsSpan().SequenceEqual(sent[i].Body))
                return $"message {i} as {Describe(arrived[i])} instead of {Describe(sent[i])}";
        }
        return null;
    }

    static string Describe(RtmpMessage m) =>
        $"csid {m.Csid} type {m.Type} timestamp {m.Timestamp} stream {m.StreamId} body {m.Body.Length}";

    /// <summary>Runs one end of a script: writes the turns belonging to this side, reads and judges the rest.</summary>
    public static async Task<int> RunDialogue(Stream ssl, List<MediaTurn> script, bool asClient, string label,
        List<string> notes, List<string> failures)
    {
        var inbound = new RtmpChunks(ssl);
        var turns = 0;
        var toServer = 0;
        var toClient = 0;
        foreach (var turn in script)
        {
            var sending = turn.FromClient == asClient;
            try
            {
                if (sending) await WriteTurn(ssl, turn).WaitAsync(TurnLimit);
                else await ReadTurn(ssl, turn, inbound, label, failures).WaitAsync(TurnLimit);
            }
            catch (Exception ex) when (ex is TimeoutException or IOException or EndOfStreamException
                                           or InvalidDataException or InvalidOperationException)
            {
                failures.Add($"{label}: turn '{turn.Label}' {(sending ? "was never written" : "never arrived whole")} " +
                             $"({ex.GetType().Name}: {ex.Message})");
                return turns;
            }

            turns++;
            if (turn.FromClient) toServer += turn.Bytes.Length; else toClient += turn.Bytes.Length;
        }

        notes.Add($"{label}: all {turns} turns carried both ways, {toServer} octets client to server and " +
                  $"{toClient} back, each read where the dialect says its message ends");
        if (script.Any(t => t.Shape == MediaRead.Chunks))
            notes.Add($"{label}: the chunk reader ended holding an inbound chunk size of {inbound.ChunkSize}");
        return turns;
    }

    private static readonly TimeSpan TurnLimit = TimeSpan.FromSeconds(10);
}

// Reads an RTMP chunk stream the way the framing is written: the basic header's format bits say how much
// of the message header repeats, the message header says how long the whole message is, and the chunk size
// says how much of it this piece may carry. A Set Chunk Size message changes that for everything after it,
// which is the one rule a relay-inside fixture cannot fake its way past.
sealed class RtmpChunks(Stream socket)
{
    private readonly MemoryStream _raw = new();
    private readonly Dictionary<int, OpenMessage> _open = new();
    private readonly Dictionary<int, MemoryStream> _parts = new();

    public int ChunkSize { get; private set; } = 128;

    record struct OpenMessage(uint Timestamp, uint Length, uint Received, byte Type, uint StreamId,
        bool Extended);

    public async Task<(byte[] Wire, List<RtmpMessage> Messages)> ReadUntil(int octets)
    {
        var messages = new List<RtmpMessage>();
        // The tally this reader keeps spans the session, so the stop condition is octets arrived since this
        // call began - compared against the running total, every turn after the first would return at once.
        var start = (int)_raw.Length;
        while (_raw.Length - start < octets)
        {
            var basic = await Take(1);
            var fmt = basic[0] >> 6;
            var csid = basic[0] & 0x3f;
            uint stamp, length, streamId;
            byte type;
            switch (fmt)
            {
                case 0:
                {
                    var head = await Take(11);
                    stamp = Media.Be24(head, 0);
                    length = Media.Be24(head, 3);
                    type = head[6];
                    streamId = Media.Le32(head, 7);
                    break;
                }
                case 1:
                {
                    var head = await Take(7);
                    stamp = Media.Be24(head, 0);
                    length = Media.Be24(head, 3);
                    type = head[6];
                    streamId = Need(csid).StreamId;
                    break;
                }
                case 2:
                {
                    var head = await Take(3);
                    stamp = Media.Be24(head, 0);
                    var previous = Need(csid);
                    length = previous.Length;
                    type = previous.Type;
                    streamId = previous.StreamId;
                    break;
                }
                default:
                {
                    var previous = Need(csid);
                    stamp = previous.Extended ? Media.RtmpExtendedTimestamp : previous.Timestamp;
                    length = previous.Length;
                    type = previous.Type;
                    streamId = previous.StreamId;
                    break;
                }
            }

            var extended = stamp == Media.RtmpExtendedTimestamp;
            var timestamp = extended ? Media.Be32(await Take(4)) : stamp;

            var received = fmt == 3 ? Need(csid).Received : 0u;
            var piece = (int)Math.Min(ChunkSize, length - received);
            // A message longer than the chunk size arrives as several pieces, and the message the reader
            // hands back is their concatenation - the declared length covers all of them, not this piece.
            var parts = fmt == 3 ? _parts[csid] : (_parts[csid] = new MemoryStream());
            parts.Write(await Take(piece));
            received += (uint)piece;
            _open[csid] = new OpenMessage(timestamp, length, received, type, streamId, extended);
            if (received < length) continue;

            _open.Remove(csid);
            _parts.Remove(csid);
            var body = parts.ToArray();
            if (type == Media.RtmpSetChunkSize) ChunkSize = (int)(Media.Be32(body) & 0x7fffffff);
            messages.Add(new RtmpMessage(csid, type, timestamp, streamId, body));
        }
        var all = _raw.ToArray();
        return (all[start..], messages);
    }

    private OpenMessage Need(int csid) =>
        _open.TryGetValue(csid, out var open) ? open
        : throw new InvalidDataException($"chunk stream {csid} continues a message this reader never started");

    private async Task<byte[]> Take(int count)
    {
        var bytes = await Media.ReadOctets(socket, count);
        _raw.Write(bytes);
        return bytes;
    }
}

// --- what the product wrote to disk -----------------------------------------------------------------

static class Capture
{
    public static async Task<string?> FindAsync(string[] before, Func<string, bool> match)
    {
        for (var i = 0; i < 50; i++)
        {
            var path = Directory.Exists("captures")
                ? Directory.GetFiles("captures").FirstOrDefault(f => !before.Contains(f) && match(f))
                : null;
            if (path != null && new FileInfo(path).Length > 0) return path;
            await Task.Delay(100);
        }
        return null;
    }

    // The writer holds the capture open for the whole session, so reading it needs a share mask that permits
    // that handle's write access - which is what File.ReadAllBytesAsync's own FileShare.Read does not.
    public static async Task<byte[]> ReadAsync(string path)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        var buffer = new byte[stream.Length];
        await stream.ReadExactlyAsync(buffer);
        return buffer;
    }

    // pcap framing: a 24-byte global header, then per packet a 16-byte record header (inclusion length at
    // offset 8) and the frame this writer builds - 14 Ethernet, 20 or 40 IP, 20 TCP. The IP length fields
    // bound the TCP payload, because an Ethernet frame under 60 octets is padded and that padding is not
    // part of the datagram. The frame's source port tells which peer sent it, so a one-sided recording
    // cannot pass for an exchange, and the TCP flags octet says what kind of segment it was.
    public static async Task<List<(bool FromServer, byte[] Payload, byte Flags)>> FramesAsync(
        string path, int upstreamPort) => Frames(await ReadAsync(path), upstreamPort);

    public static List<(bool FromServer, byte[] Payload, byte Flags)> Frames(byte[] bytes, int upstreamPort)
    {
        var frames = new List<(bool FromServer, byte[] Payload, byte Flags)>();
        for (var off = 24; off + 16 <= bytes.Length; off += 16)
        {
            var incl = (int)BitConverter.ToUInt32(bytes.AsSpan(off + 8, 4));
            if (incl < 55 || off + 16 + incl > bytes.Length) break;
            var frame = bytes.AsSpan(off + 16, incl);
            var ipv6 = frame[12] == 0x86 && frame[13] == 0xDD;
            var ipLen = ipv6 ? 40 : 20;
            var tcp = 14 + ipLen;
            var ipTotal = ipv6 ? (frame[18] << 8) | frame[19] : (frame[16] << 8) | frame[17];
            var payloadLength = Math.Max(0, ipTotal - (tcp - 14) - 20);
            frames.Add((((frame[tcp] << 8) | frame[tcp + 1]) == upstreamPort,
                frame.Slice(tcp + 20, payloadLength).ToArray(), frame[tcp + 13]));
            off += incl;   // the next record header follows this frame, not these 16 bytes
        }
        return frames;
    }

    static byte[] Joined(IEnumerable<byte[]> parts)
    {
        var all = new MemoryStream();
        foreach (var part in parts) all.Write(part);
        return all.ToArray();
    }

    /// <summary>
    /// Judges the file the proxy wrote for the session against the script it just carried. The writer
    /// records the payload of each relay chunk it was handed, so the octets of a direction joined in file
    /// order have to be exactly that direction's turns - the tunnel decrypted, in order, with nothing
    /// dropped and nothing inserted. It polls because the last turn may still be on its way into the file
    /// when the dialogue ends.
    /// </summary>
    public static async Task CheckDialogueAsync(string[] before, int upstreamPort, List<MediaTurn> script,
        string label, List<string> notes, List<string> failures)
    {
        var path = await FindAsync(before, f => f.EndsWith(".pcap", StringComparison.Ordinal) &&
                                                !f.EndsWith("_aborted.pcap", StringComparison.Ordinal) &&
                                                !f.Contains("_blind_", StringComparison.Ordinal));
        if (path == null)
        {
            failures.Add($"{label}: the session wrote no capture file to judge the tunnel against");
            return;
        }

        var wanted = new Dictionary<bool, byte[]>
        {
            [false] = Joined(script.Where(t => t.FromClient).Select(t => t.Bytes)),
            [true] = Joined(script.Where(t => !t.FromClient).Select(t => t.Bytes))
        };
        List<(bool FromServer, byte[] Payload, byte Flags)> frames = [];
        for (var attempt = 0; attempt < 30; attempt++)
        {
            frames = await FramesAsync(path, upstreamPort);
            if (wanted.All(w => Joined(frames.Where(f => f.FromServer == w.Key)
                        .Select(f => f.Payload)).AsSpan().SequenceEqual(w.Value)))
                break;
            await Task.Delay(100);
        }

        foreach (var (fromServer, bytes) in wanted)
        {
            var arrived = Joined(frames.Where(f => f.FromServer == fromServer).Select(f => f.Payload));
            if (arrived.AsSpan().SequenceEqual(bytes)) continue;
            failures.Add($"{label}: capture {Path.GetFileName(path)} holds {arrived.Length} octets " +
                         $"{(fromServer ? "from the server" : "to the server")} where the script sent " +
                         $"{bytes.Length}, first difference at " +
                         $"{Media.FirstDifference(arrived, bytes)}");
            return;
        }
        notes.Add($"{label}: capture {Path.GetFileName(path)} holds the whole dialogue, " +
                  $"{wanted[false].Length} octets to the server and {wanted[true].Length} back, in " +
                  $"{frames.Count} frames");
    }
}

// RPC records as RFC 5531 §9 lays them out and §11 frames them: a 4-octet mark whose high bit says the
// fragment behind it ends the record and whose remaining 31 bits count that fragment's octets. Both ends of
// every sunrpc fixture build the same octets, so each read stays a byte-exact comparison instead of a second
// parser that could repeat the first one's mistake.
static class Rpc
{
    // RFC 5531 §9; AUTH_TLS is the flavor RFC 9289 §7.1 assigns for the probe.
    public const uint AuthNone = 0, AuthSys = 1, AuthTls = 7;
    public const uint MsgAccepted = 0, MsgDenied = 1;
    public const uint RejectAuthError = 1, StatBadCred = 1;
    public const uint Success = 0, ProgUnavail = 1;
    private const uint Program = 100000, Version = 4;   // the rpcbind program of RFC 1833
    private const uint MsgCall = 0, MsgReply = 1, RpcVersion = 2;
    private const uint NullProc = 0;      // §12.1's PINGPROC_NULL, the procedure §4.1's probe is sent on

    public static readonly SslApplicationProtocol Alpn = new("sunrpc");   // RFC 9289 §7.2

    public static byte[] Probe(uint xid) => AuthTlsCall(xid, 0);

    // RFC 9289 §4.1 gives the probe its meaning from two words: an AUTH_TLS credential carrying no octets and
    // an AUTH_NONE verifier carrying none. Any other procedure under that credential is a misuse instead.
    public static byte[] AuthTlsCall(uint xid, uint proc) =>
        Record(Call(xid, proc, (AuthTls, []), (AuthNone, [])));

    public static byte[] NullCall(uint xid) => Record(Call(xid, 0, (AuthNone, []), (AuthNone, [])));

    // Records that read like the probe and are not, each differing from it in exactly one of the words that
    // define it. RFC 5531 §9 makes rpcvers 2 the only version - "rpcvers MUST be equal to 2" - and lets msgtype
    // pick between the call and the reply arms; §4.1 makes the credential carry no octets and the verifier be
    // AUTH_NONE of no octets. The three in the middle are not records a conforming client could send, one
    // carrying four octets more than the probe's forty and two declaring an opaque of four while carrying none,
    // so the proxy has to answer each as the ordinary record it claims to be rather than open a tunnel on
    // octets that mean no upgrade. The last is conforming but no probe: an AUTH_SYS verifier behind the
    // AUTH_TLS credential, which §4.1's "MUST be an AUTH_NONE verifier" rules out.
    public static (uint Xid, byte[] Record)[] NearProbes() =>
    [
        (0xA001, Record(CallAt(0xA001, MsgCall, 1, NullProc, (AuthTls, []), (AuthNone, [])))),
        (0xA002, Record(CallAt(0xA002, MsgReply, RpcVersion, NullProc, (AuthTls, []), (AuthNone, [])))),
        (0xA003, Record([.. Call(0xA003, NullProc, (AuthTls, []), (AuthNone, [])), 0, 0, 0, 0])),
        (0xA004, Record([.. Call(0xA004, NullProc, (AuthTls, []), (AuthNone, []))[..28],
            0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0])),
        (0xA005, Record([.. Call(0xA005, NullProc, (AuthTls, []), (AuthNone, []))[..36], 0, 0, 0, 4])),
        (0xA006, Record(Call(0xA006, NullProc, (AuthTls, []), (AuthSys, [])))),
    ];

    // A record cut in three so two fragment boundaries fall between reads (§11 lets a record carry any number
    // of fragments). The AUTH_SYS credential of Appendix A supplies octets worth cutting, and §11's fragments
    // run from 0 octets up, so the empty one in the middle is what the walk has to step over without losing
    // the record's own length.
    public static byte[][] CallFragments(uint xid)
    {
        var body = Call(xid, 11, (AuthSys, AuthSysCredential()), (AuthNone, []));
        return [Fragment(false, body[..34]), Fragment(false, []), Fragment(true, body[34..])];
    }

    public static byte[] FragmentedCall(uint xid) => Concat(CallFragments(xid));

    // The probe's own record spread over three fragments, the middle of them empty: §11 makes a record "one or
    // more record fragments" and lets each carry "0 to (2**31) - 1 bytes", so the forty octets §4.1's probe is
    // made of may arrive over any number of them. The writes cut one of the fragments in two as well, so a
    // fragment boundary and a read boundary fall inside the same record.
    public static byte[][] ProbeFragments(uint xid)
    {
        var body = Call(xid, NullProc, (AuthTls, []), (AuthNone, []));
        var last = Fragment(true, body[20..]);
        return [Fragment(false, body[..20]), Fragment(false, []), last[..16], last[16..]];
    }

    public static byte[] FragmentedProbe(uint xid) => Concat(ProbeFragments(xid));

    private static byte[] Concat(byte[][] parts)
    {
        var whole = new List<byte>();
        foreach (var part in parts) whole.AddRange(part);
        return [.. whole];
    }

    // RFC 9289 §4.1: the grant is the verifier's eight octets spelling "STARTTLS".
    public static byte[] Grant(uint xid, uint acceptStat) =>
        Record(Accepted(xid, (AuthNone, "STARTTLS"u8.ToArray()), acceptStat));

    public static byte[] AcceptedReply(uint xid) => Record(Accepted(xid, (AuthNone, []), Success));

    // §4.1 withholds the grant from a reply whose verifier does not contain the "STARTTLS" token. Eight octets
    // of AUTH_NONE that are not those eight are the one reply shape the token comparison alone separates from a
    // grant, so this is the fixture's stand-in for it.
    public static byte[] NotGrant(uint xid) => Record(Accepted(xid, (AuthNone, "TLSNOTOK"u8.ToArray()), Success));

    // §4.1 requires the reply's verifier flavor to be AUTH_NONE before it requires anything of that verifier's
    // octets, so this record has the token in the wrong place: an accepted reply whose eight octets spell
    // STARTTLS under an AUTH_SYS flavor.
    public static byte[] WrongFlavor(uint xid) =>
        Record(Accepted(xid, (AuthSys, "STARTTLS"u8.ToArray()), Success));

    public static byte[] Denial(uint xid) => Record(Denied(xid));

    private static byte[] Call(uint xid, uint proc, (uint Flavor, byte[] Body) cred,
        (uint Flavor, byte[] Body) verf) => CallAt(xid, MsgCall, RpcVersion, proc, cred, verf);

    private static byte[] CallAt(uint xid, uint msgType, uint rpcvers, uint proc,
        (uint Flavor, byte[] Body) cred, (uint Flavor, byte[] Body) verf) =>
        [.. Be(xid), .. Be(msgType), .. Be(rpcvers), .. Be(Program), .. Be(Version), .. Be(proc),
            .. Be(cred.Flavor), .. Be((uint)cred.Body.Length), .. cred.Body,
            .. Be(verf.Flavor), .. Be((uint)verf.Body.Length), .. verf.Body];

    private static byte[] Accepted(uint xid, (uint Flavor, byte[] Body) verf, uint acceptStat) =>
        [.. Be(xid), .. Be(MsgReply), .. Be(MsgAccepted), .. Be(verf.Flavor),
            .. Be((uint)verf.Body.Length), .. verf.Body, .. Be(acceptStat)];

    // §9 puts the verifier only in the MSG_ACCEPTED arm, so a refusal is five words and no more.
    private static byte[] Denied(uint xid) =>
        [.. Be(xid), .. Be(MsgReply), .. Be(MsgDenied), .. Be(RejectAuthError), .. Be(StatBadCred)];

    private static byte[] AuthSysCredential() =>
        [.. Be(0), .. Be(5), .. "probe"u8.ToArray(), 0, 0, 0, .. Be(1000), .. Be(1000), .. Be(0)];

    private static byte[] Record(byte[] body) => Fragment(true, body);

    private static byte[] Fragment(bool last, byte[] data) =>
        [.. Be((last ? 0x8000_0000u : 0u) | (uint)data.Length), .. data];

    private static byte[] Be(uint value) =>
        [(byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value];
}
