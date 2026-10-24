using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace TlsMitm;

public class MitmProxy
{
    private readonly CertEngine _certEngine;
    private readonly IRedirector _redirector;
    private readonly TcpListener _listener;
    private readonly int _listenPort;
    private readonly EchDowngrade? _echDowngrade;
    private readonly FtpSessionRegistry _ftpSessions = new();

    public MitmProxy(CertEngine certEngine, IRedirector redirector, int listenPort,
        EchDowngrade? echDowngrade = null)
    {
        _certEngine = certEngine;
        _redirector = redirector;
        _listenPort = listenPort;
        _echDowngrade = echDowngrade;
        // The redirector rewrites an outbound flow into an inbound one addressed to the client's own
        // address, which for a v6 flow is a v6 address. A socket bound to 0.0.0.0 never sees those
        // SYNs, so the listener has to span both families.
        _listener = new TcpListener(IPAddress.IPv6Any, listenPort);
        _listener.Server.DualMode = true;
    }

    public async Task StartAsync(CancellationToken ct)
    {
        _listener.Start();
        Console.WriteLine($"[Proxy] Listening on [::]:{_listenPort} (dual-stack)");

        while (!ct.IsCancellationRequested)
        {
            var client = await _listener.AcceptTcpClientAsync(ct);
            // Nothing is relayed end to end yet, so the accept loop can only name the socket's own
            // endpoints. After the redirector's swap those are (local) the client, and (remote) the
            // server whose port field carries the client's ephemeral port - logging the remote
            // address as "from" would name the server as the peer.
            var local = client.Client.LocalEndPoint as IPEndPoint;
            var remote = client.Client.RemoteEndPoint as IPEndPoint;
            Console.WriteLine($"[Proxy] Accepted connection from {local?.Address}:{remote?.Port}");
            _ = HandleClientAsync(client, ct);
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        try
        {
            var remoteEp = client.Client.RemoteEndPoint as IPEndPoint;
            var localEp = client.Client.LocalEndPoint as IPEndPoint;
            if (remoteEp == null || localEp == null)
            {
                client.Close();
                return;
            }

            var serverPort = remoteEp.Port;

            // A dual-stack listener reports an IPv4 peer as ::ffff:a.b.c.d. The redirector keys its
            // tables on the address the packet carried, so a mapped form is a guaranteed miss.
            var clientAddress = Unmap(localEp.Address);
            var serverAddress = Unmap(remoteEp.Address);
            var origDest = _redirector.LookupOriginalDest(clientAddress, serverPort, serverAddress);

            if (origDest == null)
            {
                Console.WriteLine($"[Proxy] No connection found for {clientAddress}:{serverPort} -> {serverAddress}");
                client.Close();
                return;
            }

            var (origIp, origPort) = origDest.Value;
            Console.WriteLine($"[Proxy] {clientAddress}:{serverPort} -> original dest {origIp}:{origPort}");

            // The chain a client accepts is not universal: Node/Electron verify against their bundled
            // list (emSign roots), everything else against the Windows store (Fiddler root). Classify
            // once per connection from the owning process; the result rides down to every leg.
            var identity = ClientProcess.Identify(clientAddress, serverPort, out var firstSighting);
            if (firstSighting)
            {
                var wanted = identity.Trust == ClientTrust.NodeBundled ? "emSign" : "Fiddler";
                var caveat = identity.Trust == ClientTrust.NodeBundled && !_certEngine.HonorsClientTrust
                    ? " - but this engine cannot serve it; restart with --emsign"
                    : "";
                Console.WriteLine($"[Client] pid {identity.Pid}: {identity.Label} -> {wanted} chain{caveat}");
            }

            using var realServer = await ConnectExemptedAsync(origIp, origPort, ct);
            if (realServer == null)
            {
                client.Close();
                return;
            }

            var stream = client.GetStream();
            var serverStream = realServer.GetStream();

            // Server-first protocols (SMTP/IMAP/POP3/FTP) greet before the client says anything, so
            // protocol detection cannot wait on the client alone. Peek both sockets and let whichever
            // speaks first decide; a peek consumes nothing, so the session starts with a clean stream.
            var (fromClient, firstByte) = await FirstSpeakerAsync(client.Client, realServer.Client, ct);

            if (fromClient && firstByte == 0x16)
            {
                var hello = new byte[1];
                if (await stream.ReadAsync(hello, ct) == 0) return;
                await HandleTlsAsync(client, stream, serverStream, origIp, origPort, hello[0], identity, ct);
            }
            else
            {
                await HandlePlainAsync(client, realServer, stream, serverStream, origIp, origPort, identity, ct);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Proxy] Error: {ex.Message}");
        }
        finally
        {
            client.Close();
        }
    }

    private static async Task<(bool FromClient, byte FirstByte)> FirstSpeakerAsync(
        Socket client, Socket server, CancellationToken ct)
    {
        using var race = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var clientBuf = new byte[1];
        var serverBuf = new byte[1];
        var clientPeek = client.ReceiveAsync(clientBuf, SocketFlags.Peek, race.Token).AsTask();
        var serverPeek = server.ReceiveAsync(serverBuf, SocketFlags.Peek, race.Token).AsTask();

        var winner = await Task.WhenAny(clientPeek, serverPeek);
        var fromClient = winner == clientPeek;
        byte first = 0;
        try
        {
            if (await winner > 0)
                first = fromClient ? clientBuf[0] : serverBuf[0];
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException)
        {
            // The side that could not be peeked is not carrying the session; the pump will surface it.
        }
        finally
        {
            // Cancel and drain the loser before its socket is handed to SslStream. A cancelled
            // ReceiveAsync(Peek) leaves the socket usable and, being a peek, never loses bytes.
            race.Cancel();
            await IgnoreAsync(clientPeek);
            await IgnoreAsync(serverPeek);
        }

        return (fromClient, first);
    }

    private static async Task IgnoreAsync(Task task)
    {
        try { await task; }
        catch { }
    }

    private async Task HandleTlsAsync(
        TcpClient client, Stream stream, Stream serverStream, IPAddress origIp, int origPort,
        byte firstByte, ClientIdentity identity, CancellationToken ct)
    {
        var (clientHello, rawBytes) = await ReadClientHelloAsync(stream, firstByte, ct);
        var host = ResolveTlsHost(clientHello, client, origIp, origPort);
        var helloStream = new PrefixedStream(rawBytes, stream);
        Console.WriteLine(clientHello?.ServerName != null
            ? $"[Proxy] TLS SNI: {host} (original dest: {origIp}:{origPort}){DescribeHello(clientHello)}"
            : $"[Proxy] TLS no SNI, using {host} (original dest: {origIp}:{origPort}){DescribeHello(clientHello)}");

        // An ECH hello hides the origin. RFC 9849 §6.1.6 tells a conformant client to abort with
        // "ech_required" and retry on a new connection with the server's retry_configs, and expressly
        // not to treat a rejection as a signal to disable ECH, so terminating the hello buys us nothing
        // under the spec - it is a probe against measured client behaviour (Edge 155 retried with no
        // ECH extension, or kept the terminated session). The observation is made for every hello,
        // because a retry without ECH carries the SNI we want and is one of the two proofs it worked.
        var echTerminate = _echDowngrade?.Terminate(identity.Pid, host, clientHello?.Ech == true) == true;
        var blind = clientHello?.CannotTerminate();
        if (blind != null && echTerminate) blind = null;

        if (blind != null)
        {
            await BlindRelayAsync(client, helloStream, serverStream, host, blind, origIp, origPort, ct);
            return;
        }

        // The other proof is the measured one: Edge 155 accepted the leaf named for the public name it
        // sent and kept the terminated connection, so application bytes rule out a silent revert to
        // blind relay without waiting for a retry that this client never sends.
        Action? terminationWorked = echTerminate
            ? () => _echDowngrade?.ObservedData(identity.Pid, host)
            : null;

        await MitmAsync(client, stream, rawBytes, serverStream, host, clientHello?.Alpn, origIp, origPort,
            ResolveTrust(identity, clientHello), ct, terminationWorked);
    }

    private string ResolveTlsHost(ClientHelloInfo? hello, TcpClient client, IPAddress origIp, int origPort)
    {
        if (hello?.ServerName != null) return hello.ServerName;

        // An FTPS data channel is the one TLS connection a client dials blind: the endpoint came out
        // of the control session's 227/229 reply and the name is not repeated in the handshake.
        if (client.Client.LocalEndPoint is IPEndPoint clientEp)
        {
            var owner = _ftpSessions.Lookup(Unmap(clientEp.Address), origIp, origPort);
            if (owner != null)
            {
                Console.WriteLine($"[Proxy] FTPS data channel of {owner} at {origIp}:{origPort}");
                return owner;
            }
        }

        // A missing SNI is legal: RFC 6066 §3 lets a client omit it, RFC 5246 §7.4.1.2 requires a
        // server to accept a ClientHello with no extensions at all, and RFC 9846 §9.2 permits a server
        // to demand one. An address-literal destination cannot carry a server_name (RFC 6066 §3), and
        // a partial parse still leaves replayed bytes SslStream can read, so the leaf is named from
        // the destination instead of closing the connection. An ECH client does send SNI, but it
        // should carry the public_name (RFC 9849 §6.1), so a name never matches the inner one unless
        // they coincide.
        return origIp.ToString();
    }

    private async Task MitmAsync(
        TcpClient client, Stream rawClientStream, byte[] replayedHello, Stream serverStream, string host,
        IReadOnlyList<string>? offeredAlpn, IPAddress origIp, int origPort, ClientTrust trust,
        CancellationToken ct, Action? onClientData = null)
    {
        var issued = _certEngine.GetCert(host, trust);
        Console.WriteLine($"[Proxy] Leaf issued by '{issued.Leaf.Issuer}'" +
            (issued.Chain == null ? "" : $" + {issued.Chain.Count} chain certs"));

        var sslServer = new SslStream(serverStream, false,
            (_, cert, chain, errs) => AcceptUpstreamCertificate(host, cert, chain, errs));

        // When the client offered protocols, the upstream leg is negotiated first and the client is
        // told only the one the server agreed to. Choosing independently per leg is how an h2-capable
        // client ends up sending h2 frames into a server that settled on http/1.1: the byte relay
        // cannot translate, so both peers see a protocol violation. (Measured, not from RFC 7301:
        // a TLS server that selects no protocol leaves HTTP clients on HTTP/1.1 - the baidu.com edge
        // negotiates no ALPN even when offered h2 - so an empty list toward the client matches it.)
        //
        // With no protocol to agree on, the client handshake stays first. A server may legitimately
        // delay its TLS answer until the application asks for the data - an FTPS data listener accepts
        // the connection only after RETR arrives on the control connection - so waiting on it before
        // the client has been answered deadlocks both ends.
        var upstreamFirst = offeredAlpn is { Count: > 0 };

        // The negotiated protocol has to travel from the upstream handshake to the client leg; the
        // helper returns it rather than only its success, because a bool left the client leg telling
        // nothing while the upstream was already committed to h2 - every h2 site broke that way.
        SslApplicationProtocol serverProtocol = default;
        if (upstreamFirst)
        {
            var upstream = await AuthenticateUpstreamAsync(sslServer, host, offeredAlpn, ct);
            if (!upstream.Ok) return;
            serverProtocol = upstream.Protocol;
        }

        var clientStream = new PrefixedStream(replayedHello, rawClientStream);
        Stream sslClient;
        if (issued.Chain != null)
        {
            // The emSign chain exists nowhere in the local stores, so SChannel would send the leaf
            // alone; libssl sends this exact collection instead. Only a non-default protocol is
            // announced, so a server that selected none leaves the client on HTTP/1.1.
            try
            {
                sslClient = await OpenSslServerStream.AcceptAsync(
                    rawClientStream, replayedHello, issued.Leaf, issued.Chain,
                    serverProtocol == default ? null : serverProtocol.ToString(), ct);
                Console.WriteLine($"[Proxy] Client TLS established for {host} via OpenSSL, ALPN: " +
                    $"'{((OpenSslServerStream)sslClient).NegotiatedProtocol}'");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Proxy] Client TLS failed for {host} (OpenSSL): {ex.Message}");
                return;
            }
        }
        else
        {
            var streamSsl = new SslStream(clientStream, false);
            try
            {
                var sslOptions = new SslServerAuthenticationOptions
                {
                    ServerCertificate = issued.Leaf,
                    ClientCertificateRequired = false,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                };
                if (serverProtocol != default)
                    sslOptions.ApplicationProtocols = new List<SslApplicationProtocol> { serverProtocol };
                await streamSsl.AuthenticateAsServerAsync(sslOptions, ct);
                var negotiatedProtocol = streamSsl.NegotiatedApplicationProtocol;
                Console.WriteLine($"[Proxy] Client TLS established for {host}, ALPN: {negotiatedProtocol}");
                sslClient = streamSsl;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Proxy] Client TLS failed for {host}: {ex.Message}");
                return;
            }
        }

        if (!upstreamFirst)
        {
            var upstream = await AuthenticateUpstreamAsync(sslServer, host, offeredAlpn, ct);
            if (!upstream.Ok) return;
        }

        Console.WriteLine($"[Proxy] MITM established: {host}");
        
        // Create PCAP file (connection ID in filename to avoid conflicts)
        var safeHost = string.Join("_", host.Split(Path.GetInvalidFileNameChars()));
        var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var connectionId = Guid.NewGuid().ToString("N").Substring(0, 8);
        var pcapPath = $"captures/{safeHost}_{timestamp}_{connectionId}.pcap";
        Directory.CreateDirectory("captures");
        using var pcap = new PcapWriter(pcapPath);
        Console.WriteLine($"[Proxy] Saving to {pcapPath}");
        
        // The redirector swapped the flow, so the accepted socket's local side is the client's own
        // address and its remote side is the server; the remote port is the client's ephemeral port.
        var clientEp = client.Client.LocalEndPoint as IPEndPoint;
        var clientIp = clientEp == null ? IPAddress.Loopback : Unmap(clientEp.Address);
        var clientPort = (ushort)((client.Client.RemoteEndPoint as IPEndPoint)?.Port ?? 0);
        var serverPortUshort = (ushort)origPort;

        // The control session's own plaintext is what names its data endpoints, in both directions:
        // 227/229 for passive mode, PORT/EPRT for active mode.
        var ftp = _ftpSessions.SnifferFor(clientIp, origIp, host);
        FtpActiveChannel? active = null;
        ftp.ActivePortRequest = real =>
        {
            active ??= CreateActiveChannel(host, real, trust);
            if (active == null) return null;
            active.RealClient = real;
            return active.Port;
        };

        try
        {
            await RelayAsync(sslClient, sslServer, host, clientIp, origIp, clientPort, serverPortUshort, pcap, ftp, ct, onClientData);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Proxy] Relay error for {host}: {ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            CloseActiveChannel(active);
        }
    }

    // Fiddler's rule for the upstream leg: whether to trust a server certificate is the client's
    // decision to make through the forged leaf, not a reason to kill the session here - refusing would
    // hide a server whose leaf merely expired. A blanket accept must not be a silent one, because a
    // rejected certificate and a server that refuses our hello itself leave the same log line behind.
    private static bool AcceptUpstreamCertificate(
        string host, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
    {
        if (errors == SslPolicyErrors.None) return true;

        var leaf = chain is { ChainElements.Count: > 0 } ? chain.ChainElements[0].Certificate : null;
        var san = leaf?.Extensions["2.5.29.17"]?.Format(true)?.Replace("\r\n", " ");
        Console.WriteLine($"[Upstream] {host}: accepted despite {errors}: '{certificate?.Subject}' issued by " +
            $"'{certificate?.Issuer}' {certificate?.GetEffectiveDateString()}..{certificate?.GetExpirationDateString()} SAN [{san}]");

        if (chain == null) return true;
        for (var i = 0; i < chain.ChainElements.Count; i++)
        {
            var el = chain.ChainElements[i];
            var bad = el.ChainElementStatus.Where(s => s.Status != X509ChainStatusFlags.NoError).Select(s => s.Status);
            if (!bad.Any()) continue;
            Console.WriteLine($"[Upstream] {host}: chain[{i}] '{el.Certificate.Subject}' {string.Join(",", bad)}");
        }
        return true;
    }

    private async Task HandlePlainAsync(
        TcpClient client, TcpClient realServer, Stream clientStream, Stream serverStream,
        IPAddress origIp, int origPort, ClientIdentity identity, CancellationToken ct)
    {
        Console.WriteLine($"[Proxy] Non-TLS forward to {origIp}:{origPort}");

        var session = new StartTlsSession();
        var toServer = PumpPlainAsync(clientStream, serverStream, session, isClient: true, ct);
        var toClient = PumpPlainAsync(serverStream, clientStream, session, isClient: false, ct);

        var first = await Task.WhenAny(toServer, toClient);
        if (!await first)
        {
            // One side ended: closing both sockets is the only way to unblock the peer pump,
            // which may be parked in a read that will never complete.
            client.Close();
            realServer.Close();
            await Task.WhenAll(toServer, toClient);
            return;
        }

        var other = first == toServer ? toClient : toServer;
        if (!await other)
        {
            client.Close();
            realServer.Close();
            return;
        }

        await HandleStartTlsAsync(client, clientStream, serverStream, session, origIp, origPort, identity, ct);
    }

    private static async Task<bool> PumpPlainAsync(
        Stream src, Stream dst, StartTlsSession session, bool isClient, CancellationToken ct)
    {
        var buf = new byte[8192];
        try
        {
            while (true)
            {
                if (isClient && session.AwaitingReply)
                {
                    // A conformant peer stays silent until the readiness reply, so not reading here
                    // cannot lose bytes; it keeps the socket quiescent for the TLS handover.
                    var outcome = await session.Decision.WaitAsync(ct);
                    if (outcome == StartTlsOutcome.Upgrade) return true;
                    if (outcome != StartTlsOutcome.Reject) return false;

                    if (session.ClientRemainder.Length > 0)
                    {
                        await dst.WriteAsync(session.ClientRemainder, ct);
                        await dst.FlushAsync(ct);
                        session.ClearClientRemainder();
                    }
                    continue;
                }

                var n = await src.ReadAsync(buf, ct);
                if (n == 0) break;

                var forward = n;
                if (isClient) forward = session.ScanClient(buf.AsSpan(0, n));
                else if (session.AwaitingReply) forward = session.ScanServer(buf.AsSpan(0, n));

                if (forward > 0)
                {
                    await dst.WriteAsync(buf.AsMemory(0, forward), ct);
                    await dst.FlushAsync(ct);
                }

                if (!isClient)
                {
                    var result = session.Result;
                    if (result == StartTlsOutcome.Upgrade) return true;
                    if (result == StartTlsOutcome.Abort) return false;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException or SocketException)
        {
            // The plaintext session is over; the close itself is the only outcome to report.
        }

        session.Abort();
        return false;
    }

    private async Task HandleStartTlsAsync(
        TcpClient client, Stream clientPlain, Stream serverPlain, StartTlsSession session,
        IPAddress origIp, int origPort, ClientIdentity identity, CancellationToken ct)
    {
        Console.WriteLine("[Proxy] STARTTLS accepted, upgrading connection");

        var clientRaw = new PrefixedStream(session.ClientRemainder, clientPlain);
        var serverRaw = new PrefixedStream(session.ServerRemainder, serverPlain);

        var first = new byte[1];
        var n = await clientRaw.ReadAsync(first, ct);
        if (n == 0 || first[0] != 0x16)
        {
            Console.WriteLine($"[Proxy] STARTTLS upgrade aborted: expected a ClientHello, got 0x{(n == 0 ? 0 : first[0]):X2}");
            return;
        }

        var (clientHello, rawBytes) = await ReadClientHelloAsync(clientRaw, first[0], ct);
        var host = ResolveTlsHost(clientHello, client, origIp, origPort);
        var helloStream = new PrefixedStream(rawBytes, clientRaw);
        Console.WriteLine(clientHello?.ServerName != null
            ? $"[Proxy] STARTTLS SNI: {host} (original dest: {origIp}:{origPort}){DescribeHello(clientHello)}"
            : $"[Proxy] STARTTLS no SNI, using {host} (original dest: {origIp}:{origPort}){DescribeHello(clientHello)}");

        var blind = clientHello?.CannotTerminate();
        if (blind != null)
        {
            await BlindRelayAsync(client, helloStream, serverRaw, host, blind, origIp, origPort, ct);
            return;
        }

        // A STARTTLS upgrade negotiates no application protocol, so no ALPN is offered to either
        // peer; the client never asked for one.
        await MitmAsync(client, clientRaw, rawBytes, serverRaw, host, null, origIp, origPort,
            ResolveTrust(identity, clientHello), ct);
    }

    /// <summary>
    /// Settles the chain for one connection. The owning process names most cases outright; when that
    /// process hosts both TLS stacks (an Electron main process), the hello itself decides. Chromium's
    /// BoringSSL always offers GREASE values and Node's OpenSSL never does - that asymmetry is
    /// measured on the builds this host runs, not a property of RFC 8701, which only registers the
    /// values <see cref="IsGrease"/> matches.
    /// </summary>
    private static ClientTrust ResolveTrust(ClientIdentity identity, ClientHelloInfo? hello)
    {
        if (identity.Ambiguous && hello?.Grease == true)
        {
            Console.WriteLine($"[Client] pid {identity.Pid}: GREASE in ClientHello, Chromium stack -> Fiddler chain");
            return ClientTrust.WindowsStore;
        }
        return identity.Trust;
    }

    private async Task<TcpClient?> ConnectExemptedAsync(IPAddress address, int port, CancellationToken ct)
    {
        // The socket's family is the family of the packet the client meant to send: dialing a v6
        // destination from an AF_INET socket fails before a single byte leaves.
        var family = address.AddressFamily;
        var any = family == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any;
        var socket = new Socket(family, SocketType.Stream, ProtocolType.Tcp);
        int exemptPort;
        try
        {
            socket.Bind(new IPEndPoint(any, 0));
            exemptPort = ((IPEndPoint)socket.LocalEndPoint!).Port;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Proxy] Bind failed: {ex.Message}");
            socket.Close();
            return null;
        }

        _redirector.RegisterExemption(exemptPort);
        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, port), ct);
        }
        catch
        {
            _redirector.UnregisterExemption(exemptPort);
            socket.Close();
            return null;
        }

        var client = new TcpClient { Client = socket };
        _ = UnregisterOnCloseAsync(client, exemptPort);
        return client;
    }

    private async Task UnregisterOnCloseAsync(TcpClient client, int exemptPort)
    {
        try
        {
            while (client.Connected)
                await Task.Delay(1000);
        }
        catch { }
        finally
        {
            _redirector.UnregisterExemption(exemptPort);
        }
    }

    /// <summary>
    /// Stands in for the FTP client's own data socket so the server's connect-back reaches this
    /// process. Nothing is redirected for it: the control session now advertises this listener's port
    /// instead of the client's, so the connection arrives as an ordinary local one and the outbound
    /// answer is exempted by its source port.
    /// </summary>
    private FtpActiveChannel? CreateActiveChannel(string host, IPEndPoint realClient, ClientTrust trust)
    {
        TcpListener listener;
        try
        {
            // An EPRT netid 2 names a v6 address, and the server dials that address to reach us.
            listener = new TcpListener(IPAddress.IPv6Any, 0);
            listener.Server.DualMode = true;
            listener.Start();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[FTPS] could not listen for the active-mode channel: {ex.GetType().Name}: {ex.Message}");
            return null;
        }

        var port = ((IPEndPoint)listener.LocalEndpoint!).Port;
        _redirector.RegisterExemption(port);
        Console.WriteLine($"[FTPS] active mode for {host}: listening on {port} for the client's {realClient.Port}");

        var channel = new FtpActiveChannel
        {
            Listener = listener,
            Host = host,
            Port = port,
            Trust = trust,
            RealClient = realClient
        };
        _ = AcceptActiveAsync(channel);
        return channel;
    }

    private async Task AcceptActiveAsync(FtpActiveChannel channel)
    {
        try
        {
            while (true)
            {
                var serverSide = await channel.Listener.AcceptTcpClientAsync();
                _ = HandleActiveChannelAsync(channel, serverSide);
            }
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException or InvalidOperationException)
        {
            // The control session ended and stopped the listener; no more channels are expected.
        }
    }

    private async Task HandleActiveChannelAsync(FtpActiveChannel channel, TcpClient serverSide)
    {
        var real = channel.RealClient;
        var serverEp = serverSide.Client.RemoteEndPoint as IPEndPoint;
        if (real == null || serverEp == null)
        {
            serverSide.Close();
            return;
        }
        // A dual-stack listener reports an IPv4 server as ::ffff:a.b.c.d; the capture should carry
        // the address the packet actually held.
        serverEp = new IPEndPoint(Unmap(serverEp.Address), serverEp.Port);

        Console.WriteLine($"[FTPS] active mode: {serverEp} connected, dialing the client at {real}");

        using var clientSide = await ConnectExemptedAsync(real.Address, real.Port, CancellationToken.None);
        if (clientSide == null)
        {
            Console.WriteLine($"[FTPS] active mode: nothing is listening on the client's {real}");
            serverSide.Close();
            return;
        }

        // RFC 4217 §7 assigns the TLS roles by who the peers are, not by who called connect(): "the
        // FTP client MUST be the TLS client and the FTP server MUST be the TLS server", so the client
        // is served as TLS client even though it is the peer being connected to.
        var issued = _certEngine.GetCert(channel.Host, channel.Trust);
        Stream toClient;
        try
        {
            if (issued.Chain != null)
            {
                // Same reason as the control channel: only libssl will send a chain the local stores
                // cannot build, and the data channel is verified to the same anchor.
                toClient = await OpenSslServerStream.AcceptAsync(clientSide.GetStream(),
                    ReadOnlyMemory<byte>.Empty, issued.Leaf, issued.Chain, alpn: null, CancellationToken.None);
            }
            else
            {
                var streamSsl = new SslStream(clientSide.GetStream(), false);
                await streamSsl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = issued.Leaf,
                    ClientCertificateRequired = false,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                });
                toClient = streamSsl;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[FTPS] active mode: the client refused the leaf for {channel.Host}: {ex.Message}");
            serverSide.Close();
            return;
        }

        var toServer = new SslStream(serverSide.GetStream(), false,
            (_, cert, chain, errs) => AcceptUpstreamCertificate(channel.Host, cert, chain, errs));
        try
        {
            await toServer.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = channel.Host,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
            });
        }
        catch (Exception ex)
        {
            // RFC 4217 §10.2: "It is reasonable for the server to insist that the data connection
            // uses a TLS cached session", and SslStream offers no way to present the control
            // session's session state on a second connection.
            Console.WriteLine($"[FTPS] active mode: the server refused the data-channel handshake for {channel.Host}: {ex.Message}");
            toClient.Dispose();
            toServer.Dispose();
            return;
        }

        var safeHost = string.Join("_", channel.Host.Split(Path.GetInvalidFileNameChars()));
        var pcapPath = $"captures/{safeHost}_active_{DateTime.Now:yyyyMMdd_HHmmss}_{Guid.NewGuid().ToString("N")[..8]}.pcap";
        Directory.CreateDirectory("captures");
        using var pcap = new PcapWriter(pcapPath);
        Console.WriteLine($"[FTPS] active-mode MITM established for {channel.Host}, saving to {pcapPath}");

        try
        {
            await RelayAsync(toClient, toServer, channel.Host, real.Address, serverEp.Address,
                (ushort)real.Port, (ushort)serverEp.Port, pcap, ftp: null, CancellationToken.None);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[FTPS] active-mode relay for {channel.Host}: {ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            toClient.Dispose();
            toServer.Dispose();
        }
    }

    private void CloseActiveChannel(FtpActiveChannel? channel)
    {
        if (channel == null) return;

        // Stop first: closing the listener sends packets from the exempt port, and dropping the
        // exemption before that would have them redirected.
        channel.Listener.Stop();
        _redirector.UnregisterExemption(channel.Port);
    }

    /// <summary>
    /// Collapses the ::ffff:a.b.c.d form a dual-stack socket reports for an IPv4 peer back to the
    /// address the packet carried, so connection tables, captures and FTP keys all agree.
    /// </summary>
    private static IPAddress Unmap(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    private static async Task<(ClientHelloInfo? info, byte[] rawBytes)> ReadClientHelloAsync(Stream stream, byte firstByte, CancellationToken ct)
    {
        var buffer = new byte[16384];
        buffer[0] = firstByte;
        var totalRead = 1;

        while (totalRead < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(totalRead), ct);
            if (read == 0) break;
            totalRead += read;

            if (totalRead > 5)
            {
                var recordLen = (buffer[3] << 8) | buffer[4];
                if (totalRead >= 5 + recordLen)
                    break;
            }
        }

        var rawBytes = buffer.AsSpan(0, totalRead).ToArray();

        if (totalRead < 43) return (null, rawBytes);

        // Whatever arrived in the same read past the end of the ClientHello record is the client's next
        // flight: the early data itself for a 0-RTT hello, after the dummy change_cipher_spec record
        // that RFC 9846 Appendix E.4 has early-data clients send right behind the ClientHello.
        var firstRecordLen = (buffer[3] << 8) | buffer[4];
        var afterHello = Math.Max(0, totalRead - (5 + firstRecordLen));

        var offset = 43;
        var sessionIdLen = buffer[offset];
        offset += 1 + sessionIdLen;

        if (offset + 2 > totalRead) return (null, rawBytes);
        var cipherLen = (buffer[offset] << 8) | buffer[offset + 1];
        bool grease = false;
        for (var i = offset + 2; i + 1 < offset + 2 + cipherLen && i + 1 < totalRead; i += 2)
            grease |= IsGrease((buffer[i] << 8) | buffer[i + 1]);
        offset += 2 + cipherLen;

        if (offset >= totalRead) return (null, rawBytes);
        var compLen = buffer[offset];
        offset += 1 + compLen;

        if (offset + 2 > totalRead) return (null, rawBytes);
        var extTotalLen = (buffer[offset] << 8) | buffer[offset + 1];
        offset += 2;

        string? name = null;
        var alpn = new List<string>();
        bool tls13 = false, psk = false, pskDhe = false, earlyData = false, ech = false;

        var extEnd = offset + extTotalLen;
        while (offset + 4 <= extEnd && offset + 4 <= totalRead)
        {
            var extType = (buffer[offset] << 8) | buffer[offset + 1];
            var extLen = (buffer[offset + 2] << 8) | buffer[offset + 3];
            var dataStart = offset + 4;
            var dataEnd = dataStart + extLen;
            if (dataEnd > totalRead) break;
            offset = dataEnd;
            grease |= IsGrease(extType);

            switch (extType)
            {
                case 0x0000 when dataStart + 5 <= dataEnd && buffer[dataStart + 2] == 0:
                {
                    var nameLen = (buffer[dataStart + 3] << 8) | buffer[dataStart + 4];
                    var nameStart = dataStart + 5;
                    if (nameStart + nameLen <= dataEnd)
                        name = Encoding.ASCII.GetString(buffer, nameStart, nameLen);
                    break;
                }
                // application_layer_protocol_negotiation, RFC 7301 §3.1: "ProtocolName
                // protocol_name_list<2..2^16-1>" holding "opaque ProtocolName<1..2^8-1>" entries, in
                // the client's order of preference. The list length is skipped rather than enforced.
                case 0x0010 when dataStart + 2 <= dataEnd:
                {
                    var p = dataStart + 2;
                    while (p < dataEnd)
                    {
                        int nameLen = buffer[p];
                        p += 1;
                        if (p + nameLen > dataEnd) break;
                        alpn.Add(Encoding.ASCII.GetString(buffer, p, nameLen));
                        p += nameLen;
                    }
                    break;
                }
                case 0x002b:
                    // supported_versions, RFC 9846 §4.3.1: a length-prefixed list of 2-octet versions.
                    for (var i = dataStart + 1; i + 1 < dataEnd; i += 2)
                        if (((buffer[i] << 8) | buffer[i + 1]) == 0x0304) tls13 = true;
                    break;
                case 0x0029: psk = true; break;                  // pre_shared_key, RFC 9846 §4.3.11
                case 0x002d:                                     // psk_key_exchange_modes, RFC 9846 §4.3.9
                    // psk_ke(0) is PSK-only: the server supplies no key_share, so no ephemeral secret
                    // exists for a proxy to learn; psk_dhe_ke(1) keeps the DHE exchange (and is the only
                    // mode a MITM can terminate).
                    for (var i = dataStart + 1; i < dataEnd; i++)
                        if (buffer[i] == 0x01) pskDhe = true;
                    break;
                case 0x002a: earlyData = true; break;            // early_data, RFC 9846 §4.3.10
                // encrypted_client_hello (RFC 9849 §5, IANA value 65037 = 0xfe0d). Nothing else in the
                // range is meaningful here, so the match is exact rather than a block.
                case 0xfe0d: ech = true; break;
            }
        }

        return (new ClientHelloInfo(name, alpn, tls13, psk, psk && !pskDhe, earlyData, ech, grease, afterHello), rawBytes);
    }

    // RFC 8701 §2 registers values whose two bytes are equal with a low nibble of 0xA for extensions,
    // groups, signature algorithms and versions. Whether a given stack sends them is measured here:
    // the Chromium family does, which distinguishes its stack from Node inside one process.
    private static bool IsGrease(int value) =>
        (value & 0x0F0F) == 0x0A0A && (value >> 8) == (value & 0xFF);

    private static async Task RelayAsync(Stream a, Stream b, string host, IPAddress clientIp, IPAddress serverIp, ushort clientPort, ushort serverPort, PcapWriter pcap, FtpControlSniffer? ftp, CancellationToken ct, Action? onClientData = null)
    {
        try
        {
            await Task.WhenAll(
                RelayOneWay(a, b, "client→server", host, clientIp, serverIp, clientPort, serverPort, true, pcap, ftp, ct, onClientData),
                RelayOneWay(b, a, "server→client", host, serverIp, clientIp, serverPort, clientPort, false, pcap, ftp, ct)
            );
        }
        catch (IOException) { }
        catch (OperationCanceledException) { }
    }

    private static async Task RelayOneWay(Stream src, Stream dst, string direction, string host, IPAddress srcIp, IPAddress dstIp, ushort srcPort, ushort dstPort, bool isOutbound, PcapWriter pcap, FtpControlSniffer? ftp, CancellationToken ct, Action? onFirstData = null)
    {
        var buf = new byte[8192];
        long totalBytes = 0;
        int readCount = 0;
        bool notified = false;
        int n;
        // Which pump ended and why is the whole diagnosis for a stalled session: a clean EOF, a TLS
        // alert and a socket error all look identical from the byte tally alone.
        var ended = "eof";
        try
        {
            while ((n = await src.ReadAsync(buf, ct)) > 0)
            {
                var payload = buf.AsMemory(0, n);
                ReadOnlyMemory<byte> forward;

                // Tapping and rewriting happen before the write: a recorded FTP endpoint has to be
                // known before the peer reads the reply and opens the data connection, and a
                // substituted PORT has to reach the server before it acts on it.
                if (isOutbound)
                {
                    var rewritten = ftp?.RewriteClient(payload.Span);
                    forward = rewritten ?? payload;
                }
                else
                {
                    ftp?.TapServer(payload.Span);
                    forward = payload;
                }

                if (forward.Length == 0) continue;

                await dst.WriteAsync(forward, ct);
                await dst.FlushAsync(ct);

                // Save to PCAP
                pcap.WritePacket(forward.ToArray(), isOutbound, srcIp, dstIp, srcPort, dstPort);

                // Only after the bytes reached the peer: a write that failed proves nothing about the
                // handshake being accepted.
                if (!notified)
                {
                    notified = true;
                    onFirstData?.Invoke();
                }

                totalBytes += n;
                readCount++;
            }
        }
        catch (IOException ex) { ended = $"io: {ex.Message}"; }
        catch (ObjectDisposedException) { ended = "disposed"; }
        Console.WriteLine($"[Proxy] Relay {direction} closed ({ended}) for {host}, {totalBytes} bytes in {readCount} reads");

        // Propagating EOF as a bare FIN is a truncation attack to a strict TLS peer: curl/Schannel
        // aborts with "server closed abruptly (missing close_notify)" and discards the completed
        // transfer. SslStream has no half-close, but ShutdownAsync emits the alert itself.
        try
        {
            if (dst is SslStream tls)
                await tls.ShutdownAsync().WaitAsync(TimeSpan.FromSeconds(2), CancellationToken.None);
            else if (dst is OpenSslServerStream openssl)
                await openssl.ShutdownAsync(TimeSpan.FromSeconds(2));
            else
                await dst.FlushAsync(CancellationToken.None);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException
            or OperationCanceledException or TimeoutException)
        {
            // The peer is already gone or will not answer the alert; closing is all that is left.
        }
        finally
        {
            try { dst.Close(); } catch { }
        }
    }

    private record ClientHelloInfo(
        string? ServerName, IReadOnlyList<string> Alpn, bool Tls13, bool PskOffered, bool PskOnly,
        bool EarlyData, bool Ech, bool Grease, int AfterHello)
    {
        /// <summary>
        /// Names the handshake shapes we cannot terminate, or null when we can. Relaying the bytes
        /// untouched keeps such a session alive end to end and still captures every packet; terminating
        /// it would do neither. The three reasons are structural: ECH encrypts the inner ClientHello
        /// to a key only the server holds (RFC 9849 §5); 0-RTT encrypts the early data under the
        /// PSK, which a terminated handshake never learns (RFC 9846 §2.3, §4.3.10); and psk_ke(0)
        /// supplies no key_share at all, leaving no ephemeral secret to obtain (RFC 9846 §4.3.9).
        /// ECH is the one shape a caller may deliberately terminate instead, as the retry probe
        /// <see cref="EchDowngrade"/> describes.
        /// </summary>
        public string? CannotTerminate()
        {
            if (Ech) return "ECH - the inner hello is encrypted for the server's own key";
            if (EarlyData && PskOffered) return "0-RTT - the client sends early data we cannot decrypt";
            if (PskOnly) return "PSK-only resumption - the client allows no ECDHE fallback";
            return null;
        }
    }

    private static string DescribeHello(ClientHelloInfo? hello)
    {
        if (hello == null) return " [hello unparseable]";
        var s = new StringBuilder(hello.Tls13 ? " tls1.3" : " tls<=1.2");
        if (hello.Alpn.Count > 0) s.Append($" alpn={string.Join(",", hello.Alpn)}");
        if (hello.PskOffered) s.Append(hello.PskOnly ? " psk-only" : " psk");
        if (hello.EarlyData) s.Append(" early_data");
        if (hello.Ech) s.Append(" ech");
        // Chromium's BoringSSL always offers GREASE values and Node's OpenSSL never does (measured
        // on the builds this host runs); on a process that hosts both stacks, this is the
        // per-connection tell.
        if (hello.Grease) s.Append(" grease");
        if (hello.AfterHello > 0) s.Append($" +{hello.AfterHello}B-after-hello");
        return s.ToString();
    }

    private async Task<(bool Ok, SslApplicationProtocol Protocol)> AuthenticateUpstreamAsync(
        SslStream sslServer, string host, IReadOnlyList<string>? offeredAlpn, CancellationToken ct)
    {
        var authOptions = new SslClientAuthenticationOptions
        {
            TargetHost = host,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
        };
        // Offering exactly what the client offered keeps us from inventing a protocol it never asked
        // for; with nothing offered the extension is omitted. The server selects from the client's
        // list or fails with no_application_protocol (RFC 7301 §3.2), and HTTP/2 over TLS is
        // identified only by the "h2" ALPN ID (RFC 9113 §3.1), so an HTTP client that offered nothing
        // stays on HTTP/1.1.
        if (offeredAlpn is { Count: > 0 })
            authOptions.ApplicationProtocols = offeredAlpn.Select(p => new SslApplicationProtocol(p)).ToList();

        try
        {
            await sslServer.AuthenticateAsClientAsync(authOptions, ct);
            var protocol = sslServer.NegotiatedApplicationProtocol;
            Console.WriteLine($"[Proxy] Server TLS established, ALPN: {protocol} (client offered: {DescribeAlpn(offeredAlpn)})");
            return (true, protocol);
        }
        catch (Exception ex)
        {
            // A refused hello names nothing but the exception unless the hello itself is on the line:
            // offered protocols and ALPN are how this differs from the certificate cases logged above.
            Console.WriteLine($"[Proxy] Server TLS failed for {host}: {ex.Message} (alpn: {DescribeAlpn(offeredAlpn)}, protocols: {authOptions.EnabledSslProtocols})");
            return (false, default);
        }
    }

    private static string DescribeAlpn(IReadOnlyList<string>? alpn) =>
        alpn is { Count: > 0 } ? string.Join(",", alpn) : "none";

    /// <summary>
    /// Relays a session that cannot be terminated: the bytes the client already sent are replayed to the
    /// real server verbatim, so the handshake the client asked for happens end to end.
    /// </summary>
    private async Task BlindRelayAsync(
        TcpClient client, Stream clientStream, Stream serverStream, string host, string reason,
        IPAddress origIp, int origPort, CancellationToken ct)
    {
        Console.WriteLine($"[Proxy] Blind relay to {origIp}:{origPort} for {host}: {reason}");

        var safeHost = string.Join("_", host.Split(Path.GetInvalidFileNameChars()));
        var pcapPath = $"captures/{safeHost}_blind_{DateTime.Now:yyyyMMdd_HHmmss}_{Guid.NewGuid().ToString("N")[..8]}.pcap";
        Directory.CreateDirectory("captures");
        using var pcap = new PcapWriter(pcapPath);
        Console.WriteLine($"[Proxy] Saving to {pcapPath}");

        var clientEp = client.Client.LocalEndPoint as IPEndPoint;
        var clientIp = clientEp == null ? IPAddress.Loopback : Unmap(clientEp.Address);
        var clientPort = (ushort)((client.Client.RemoteEndPoint as IPEndPoint)?.Port ?? 0);

        try
        {
            await RelayAsync(clientStream, serverStream, host, clientIp, origIp, clientPort,
                (ushort)origPort, pcap, ftp: null, ct);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Proxy] Blind relay error for {host}: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private class PrefixedStream : Stream
    {
        private readonly byte[] _prefix;
        private readonly Stream _inner;
        private int _prefixOffset;

        public PrefixedStream(byte[] prefix, Stream inner)
        {
            _prefix = prefix;
            _inner = inner;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => _inner.CanWrite;
        public override long Length => _prefix.Length + _inner.Length;
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            if (_prefixOffset < _prefix.Length)
            {
                var remaining = _prefix.Length - _prefixOffset;
                var toCopy = Math.Min(remaining, buffer.Length);
                _prefix.AsSpan(_prefixOffset, toCopy).CopyTo(buffer);
                _prefixOffset += toCopy;
                return toCopy;
            }
            return _inner.Read(buffer);
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_prefixOffset < _prefix.Length)
            {
                var remaining = _prefix.Length - _prefixOffset;
                var toCopy = Math.Min(remaining, buffer.Length);
                _prefix.AsMemory(_prefixOffset, toCopy).CopyTo(buffer);
                _prefixOffset += toCopy;
                return new ValueTask<int>(toCopy);
            }
            return _inner.ReadAsync(buffer, cancellationToken);
        }

        public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => _inner.WriteAsync(buffer, offset, count, cancellationToken);
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => _inner.WriteAsync(buffer, cancellationToken);
        public override void Flush() => _inner.Flush();
        public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing) _inner.Dispose();
            base.Dispose(disposing);
        }
    }
}
