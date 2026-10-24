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
    var liveHost = mode == "live-ftps" ? "sft.rohde-schwarz.com" : null;
    const int livePort = 990;
    var livePath = "/packages/rs_mrt-debian-cmx500/dists/kirkstone/Release.gpg";
    var isLive = liveHost != null;

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

    var serverTask = Task.Run(async () =>
    {
        if (isLive) return;
        // Auto serves a Node/Electron client followed by the probe itself (Windows store), which must
        // receive different chains. The first leg is optional because current clients may reject the
        // legacy eMSign root before completing the handshake.
        var acceptCount = mode == "auto" ? 2
            : mode is "grease" or "rootcheck" ? 0 : 1;
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
            case "xmpp": await ServeXmppAsync(stream, upstreamCert); break;
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
            // alpn-fallback: the upstream is a server with no ALPN at all, exactly like baidu's edge.
            case "alpn-fallback": await ServeImplicitAsync(stream, upstreamCert); break;
            case "emsign": await ServeOptionalImplicitAsync(stream, upstreamCert); break;
            case "auto":
                if (i == 0) await ServeOptionalImplicitAsync(stream, upstreamCert);
                else await ServeImplicitAsync(stream, upstreamCert);
                break;
            case "alpn-h2": await ServeImplicitH2Async(stream, upstreamCert); break;
            case "smtpsplit": await ServeSmtpSplitAsync(stream, upstreamCert); break;
            case "https-close": await ServeHttpsCloseAsync(stream, upstreamCert, serverNotes); break;
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
    var emSignCas = mode is "emsign" or "auto" ? LoadEmSignCas() : new List<EmSignCa>();
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
        else if (mode == "grease")
        {
            // Parsing only: the decision is made before any socket exists, so no traffic is needed.
            await CheckGreaseAsync(notes, failures);
        }
        else if (mode == "rootcheck")
        {
            CheckRootSelection(rootForClient, notes, failures);
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
        else if (isLive)
        {
            await RunLiveFtpsAsync(proxyPort, rootPemPath!, liveHost!, livePort, livePath, notes, failures)
                .WaitAsync(TimeSpan.FromSeconds(90));
        }
        else
        {
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(loopbackIp, proxyPort);
            await RunClientAsync(mode, tcp.GetStream(), notes).WaitAsync(TimeSpan.FromSeconds(20));
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
            case "xmpp": await ClientXmppAsync(s, notes); break;
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
            case "alpn-h2": await ClientAlpnH2Async(s, "probe.test", notes); break;
            case "smtpsplit": await ClientSmtpSplitAsync(s, notes); break;
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

    static async Task ClientXmppAsync(NetworkStream s, List<string> notes)
    {
        await ExpectAsync(s, "<?xml");
        await SendAsync(s, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>\r\n");
        await ExpectAsync(s, "<proceed");

        // acceptAny because nothing is terminated on this leg: the certificate in view is the fake
        // upstream's own self-signed one, not a leaf the proxy signed.
        var ssl = await UpgradeAsync(s, "probe.test", notes, acceptAny: true);
        await SendAsync(ssl, "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='ANONYMOUS'/>\r\n");
        await ExpectAsync(ssl, "<success");
        notes.Add("xmpp: the relay left the XML dialect alone and carried the TLS handshake through untouched");
    }

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

    static async Task<SslStream> UpgradeWithoutSniAsync(Stream raw, List<string> notes)
    {
        var ssl = new SslStream(raw, false, (_, cert, _, errors) =>
        {
            // The name is not what this mode measures; the leaf's own SAN is, so accept any policy
            // verdict here and assert the identity from the certificate after the handshake.
            notes.Add($"data handshake leaf='{cert?.Subject}' policyErrors={errors}");
            return true;
        });
        // No target name means no server_name extension: exactly what the proxy cannot read off the wire.
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = "" });
        notes.Add($"data TLS={ssl.SslProtocol} alpn='{ssl.NegotiatedApplicationProtocol}'");
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

    static async Task<SslStream> UpgradeAsync(Stream raw, string host, List<string> notes, bool acceptAny = false)
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
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = host });
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
    // §5.4.2), which this classifier does not read, so the session has to survive as a blind relay - the
    // handshake and everything after it reach the real server untouched.
    static async Task ServeXmppAsync(NetworkStream s, X509Certificate2 cert)
    {
        await SendAsync(s, "<?xml version='1.0'?><stream:stream from='probe.test' xmlns='jabber:client' version='1.0'>\r\n");
        await ExpectAsync(s, "<starttls");
        await SendAsync(s, "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>\r\n");

        using var ssl = new SslStream(s, false);
        await ssl.AuthenticateAsServerAsync(cert);
        await ExpectAsync(ssl, "<auth");
        await SendAsync(ssl, "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>\r\n");
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

    // A 0-RTT first flight: a ClientHello offering a PSK plus early_data, then the application data the
    // client sent before the handshake finished. Neither is readable by the proxy, so what is under test is
    // that the real server receives both byte for byte and the client still gets its reply back.
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
        Ext(ext, 0x002d, new byte[] { 1, 0x01 });

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
        notes.Add($"early-data: {flight.Length}-byte 0-RTT flight relayed, reply '{reply.Split("\r\n")[0]}'");
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
        await ExpectAsync(ssl, "GET");
        await SendAsync(ssl, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
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
        string? path = null;
        for (var i = 0; i < 50 && path == null; i++)
        {
            path = Directory.Exists("captures")
                ? Directory.GetFiles("captures").FirstOrDefault(f => !before.Contains(f) && new FileInfo(f).Length > 0)
                : null;
            if (path == null) await Task.Delay(100);
        }
        if (path == null)
        {
            failures.Add("ipv6: no capture file was written");
            return;
        }

        const int frame = 24 + 16;
        var bytes = await File.ReadAllBytesAsync(path);
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

        var ambiguous = new ClientIdentity(ClientTrust.NodeBundled, 1, "test", true);
        var decided = (ClientTrust)resolve.Invoke(null, new object?[] { ambiguous, chromium })!;
        var kept = (ClientTrust)resolve.Invoke(null, new object?[] { ambiguous, node })!;
        if (decided != ClientTrust.WindowsStore)
            failures.Add("grease: an ambiguous process sending GREASE was not moved to the Fiddler chain");
        if (kept != ClientTrust.NodeBundled)
            failures.Add("grease: an ambiguous process without GREASE lost its emSign chain");
        notes.Add($"grease: ambiguous pid -> chromium='{decided}' node='{kept}'");
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

    static async Task RunEmsignClientAsync(int proxyPort, List<string> notes, List<string> failures)
    {
        var electron = Environment.GetEnvironmentVariable("TLSMITM_ELECTRON")
            ?? @"C:\Users\meowthink\AppData\Local\Programs\Qoder CN\Qoder CN.exe";
        var node = Environment.GetEnvironmentVariable("TLSMITM_NODE");
        var useElectron = node == null && File.Exists(electron);
        var executable = node ?? (useElectron ? electron : "node");
        var clientName = useElectron ? "electron" : "node";

        var script = Path.Combine(Path.GetTempPath(), $"emsign-client-{Environment.ProcessId}.js");
        File.WriteAllText(script, """
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
            """);

        var psi = new ProcessStartInfo(executable, $"\"{script}\" {proxyPort} probe.test")
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
            return;
        }

        using (process)
        {
            var stdout = await process.StandardOutput.ReadToEndAsync();
            var stderr = await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();
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

    // With the machine-store opt-in set, CI otherwise signs with a certificate the product's own
    // discovery would never reach. This mode calls RootCa anyway and prints which root it returned, so
    // the log carries the comparison instead of leaving it to the workflow comment.
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
            notes.Add($"rootcheck: RootCa's CurrentUser\\Root enumeration returned no usable root " +
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
}

sealed class FakeRedirector : IRedirector
{
    private readonly Func<int, IPEndPoint> _targetFor;
    private int _lookupIndex;

    public FakeRedirector(Func<int, IPEndPoint> targetFor) => _targetFor = targetFor;

    // Connections are handed their original destination in arrival order: control first, then the
    // data channel it opens later, which is the only way the harness can model an ephemeral port.
    public (IPAddress ip, int port)? LookupOriginalDest(IPAddress clientIp, int clientPort, IPAddress serverIp)
    {
        var target = _targetFor(Interlocked.Increment(ref _lookupIndex) - 1);
        return (target.Address, target.Port);
    }

    public void RegisterExemption(int sourcePort) { }

    public void UnregisterExemption(int sourcePort) { }

    public void RegisterLocalService(int dstPort) { }
}
