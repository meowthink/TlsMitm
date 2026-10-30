using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Router;

namespace Router;

// The two LAN-side listeners. They are thin on purpose: every decision lives in DhcpServer and
// DnsServer, which tests/servcheck drives with bytes and no sockets at all. Where a reply is sent -
// including the port - is decided there too, and this only carries the bytes.
public static class Services
{
    // Bound here rather than inside the loop so a port already taken is reported to the console instead
    // of faulting a task nobody awaits.
    public static UdpClient? OpenListener(uint lanAddress, ushort port, bool forBroadcast)
    {
        try
        {
            var socket = new UdpClient(new IPEndPoint(Host.ToIpAddress(lanAddress), port));
            if (forBroadcast) socket.EnableBroadcast = true;
            return socket;
        }
        catch (SocketException ex)
        {
            Console.WriteLine($"[Router] Cannot bind {NatTable.FormatAddress(lanAddress)}:{port} - {ex.Message}");
            return null;
        }
    }

    public static async Task RunDhcp(UdpClient socket, DhcpServer server, uint lanAddress,
        LanProbe probe, CancellationToken token)
    {
        Console.WriteLine($"[Router] DHCP on {NatTable.FormatAddress(lanAddress)}:{DhcpPorts.ServerPort}, " +
                          $"pool {NatTable.FormatAddress(server.PoolStart)}+{server.PoolCount}");
        server.Leased += lease => Console.WriteLine(
            $"[Router] lease {NatTable.FormatAddress(lease.Address)} client={lease.Client} " +
            $"host={lease.HostName ?? "-"} expires={lease.Expires:HH:mm:ss}");

        while (!token.IsCancellationRequested)
        {
            UdpReceiveResult request;
            try
            {
                request = await socket.ReceiveAsync(token).ConfigureAwait(false);
            }
            // Cancelling throws; disposing the socket at shutdown makes a pending receive fault instead,
            // and both mean the same thing here.
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException)
            {
                return;
            }
            catch (SocketException ex)
            {
                Console.WriteLine($"[Router] DHCP receive failed: {ex.Message}");
                return;
            }

            // Before anything else, so a probe leaves no trace in the lease table behind it.
            if (TookProbe(probe, request)) continue;
            // Reaped here rather than from a timer: the lease tables have one owner, and an address a
            // client has stopped renewing has to be free again before the next DISCOVER is answered.
            server.Sweep();
            // Every datagram that arrives has to leave a line, because a request this loop drops and a
            // request that never arrived print the same thing: nothing. The catch is the same reasoning -
            // this task is nobody's awaited child, so an exception here would end the listener in silence.
            DhcpReply? reply;
            try
            {
                if (!server.TryReply(request.Buffer, out reply) || reply is null)
                {
                    Console.WriteLine($"[Router] dhcp ignored {request.Buffer.Length} octets from {request.RemoteEndPoint}");
                    continue;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Router] dhcp request failed: {ex.GetType().Name}: {ex.Message}");
                continue;
            }
            // Printed before it is sent, because the console is the only place this lease is visible: the
            // hosted-network adapter is not in any capture tool's list, so the client's own view of what
            // it was told cannot be read off the wire here.
            Console.WriteLine($"[Router] dhcp {reply.Kind} " +
                              $"{NatTable.FormatAddress(BinaryPrimitives.ReadUInt32BigEndian(reply.Bytes.AsSpan(16, 4)))} " +
                              $"-> {NatTable.FormatAddress(reply.DestinationIp)}:{reply.DestinationPort} " +
                              DhcpFormat.DescribeOptions(reply.Bytes));
            try
            {
                // Never the sender's endpoint: a client with no address sends from 0.0.0.0, and a relayed
                // request arrives from the agent rather than from the client, so the destination address
                // and port both have to come out of the message - ciaddr or the limited broadcast on port
                // 68 for a client, giaddr on port 67 for the agent that forwarded it (RFC 2131 §4.1).
                await socket.SendAsync(reply.Bytes,
                    new IPEndPoint(Host.ToIpAddress(reply.DestinationIp), reply.DestinationPort)).ConfigureAwait(false);
            }
            catch (SocketException ex)
            {
                Console.WriteLine($"[Router] DHCP reply to {NatTable.FormatAddress(reply.DestinationIp)} " +
                                  $"({reply.Kind}) failed: {ex.Message}");
            }
        }
    }

    public static async Task RunDns(UdpClient socket, DnsServer server, uint lanAddress,
        LanProbe probe, CancellationToken token)
    {
        server.Queried += (name, type, client) =>
            Console.WriteLine($"[Router] dns {NatTable.FormatAddress(client)} -> {name} type={type}");

        while (!token.IsCancellationRequested)
        {
            UdpReceiveResult request;
            try
            {
                request = await socket.ReceiveAsync(token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException)
            {
                return;
            }
            catch (SocketException ex)
            {
                Console.WriteLine($"[Router] DNS receive failed: {ex.Message}");
                return;
            }

            if (TookProbe(probe, request)) continue;
            // Same reason as in RunDhcp, and no cheaper to defer: an entry past its TTL is already not
            // served (TryRespond compares UsableUntil), so this only stops the table growing.
            server.Sweep();

            // Read, then hand off to a pool thread: this loop's only job is to be back at Receive. The
            // Task.Run is not cosmetic - AnswerDnsQuery runs synchronously up to its send, and TryRespond
            // waits on the upstream inside that, so calling it here would leave the loop inside the wait
            // rather than reading the next datagram.
            _ = Task.Run(() => AnswerDnsQuery(socket, server, request), token);
        }
    }

    private static async Task AnswerDnsQuery(UdpClient socket, DnsServer server, UdpReceiveResult request)
    {
        byte[]? reply;
        try
        {
            if (!server.TryRespond(request.Buffer, Host.ToBigEndian(request.RemoteEndPoint.Address), out reply))
                return;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Router] DNS query failed: {ex.Message}");
            return;
        }
        if (reply is null) return;
        // RFC 1035 §4.2.1 answers an over-long UDP message by cutting it and setting TC, and the
        // client that sees TC retries the same question over TCP - which RunDnsTcp serves below.
        // Sending nothing instead, as this did, leaves the client with a timeout it cannot act on.
        if (reply.Length > DnsFormat.UdpMessageLimit)
        {
            var cut = DnsFormat.TruncateForUdp(reply);
            if (cut is null)
            {
                Console.WriteLine($"[Router] DNS answer for {request.RemoteEndPoint} is {reply.Length} octets " +
                                  $"and cannot be cut to {DnsFormat.UdpMessageLimit}: the question it echoes is longer than that");
                return;
            }
            Console.WriteLine($"[Router] DNS answer for {request.RemoteEndPoint} is {reply.Length} octets: " +
                              $"truncated to {cut.Length} with TC set, retry it over TCP");
            reply = cut;
        }
        try
        {
            await socket.SendAsync(reply, request.RemoteEndPoint).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
        {
            // Disposed is the run ending under a query still in flight; there is nobody left to tell.
            if (ex is SocketException) Console.WriteLine($"[Router] DNS reply failed: {ex.Message}");
        }
    }

    public static TcpListener? OpenTcpListener(uint lanAddress, ushort port)
    {
        try
        {
            var listener = new TcpListener(Host.ToIpAddress(lanAddress), port);
            listener.Start();
            return listener;
        }
        catch (SocketException ex)
        {
            Console.WriteLine($"[Router] Cannot bind TCP {NatTable.FormatAddress(lanAddress)}:{port} - {ex.Message}");
            return null;
        }
    }

    // The TCP half of the same resolver. A client that was handed a truncated UDP answer asks the same
    // question here, and RFC 1035 §4.2.2 is what makes this leg necessary rather than a nicety: "DNS
    // servers that support UDP implementations MUST implement the TCP protocol".
    public static async Task RunDnsTcp(TcpListener listener, DnsServer server, uint lanAddress,
        CancellationToken token)
    {
        Console.WriteLine($"[Router] DNS on {NatTable.FormatAddress(lanAddress)}:{DnsPorts.ServerPort} over TCP too, " +
                          "for the retry a truncated UDP answer calls for");
        while (!token.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Router] DNS accept failed: {ex.GetType().Name}: {ex.Message}");
                return;
            }

            // One connection is one client's retry, and a retry can be as slow as the UDP question that
            // sent it there. Serving it on the accept loop would queue every other client behind it.
            _ = Task.Run(() => ServeDnsClient(client, server));
        }
    }

    private static void ServeDnsClient(TcpClient client, DnsServer server)
    {
        using (client)
        {
            // One query and one answer per connection is what a resolver's own retry sends, so the
            // connection is not kept and the stream is not looped. The timeouts bound a peer that
            // connects and says nothing.
            client.ReceiveTimeout = 4000;
            client.SendTimeout = 4000;
            var peer = Host.ToBigEndian(((IPEndPoint)client.Client.RemoteEndPoint!).Address);
            try
            {
                var stream = client.GetStream();
                ServeDnsConnection(stream, stream, server, peer);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Router] DNS over TCP from {NatTable.FormatAddress(peer)} failed: " +
                                  $"{ex.GetType().Name}: {ex.Message}");
            }
        }
    }

    // RFC 1035 §4.2.2: on a TCP connection "the message length field is a two octet unsigned 16-bit
    // integer specifying the length of the following message", and the 512-octet ceiling of §4.2.1 does
    // not apply - which is the whole reason a truncated answer goes this way. Split out from the
    // listener so tests/servcheck drives it over a MemoryStream with no socket.
    public static void ServeDnsConnection(Stream input, Stream output, DnsServer server, uint clientAddress)
    {
        var prefix = new byte[2];
        if (!ReadExactly(input, prefix)) return;
        var query = new byte[BinaryPrimitives.ReadUInt16BigEndian(prefix)];
        if (!ReadExactly(input, query)) return;

        if (!server.TryRespond(query, clientAddress, out byte[]? reply) || reply is null) return;
        var framed = new byte[reply.Length + 2];
        BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)reply.Length);
        reply.CopyTo(framed.AsSpan(2));
        output.Write(framed);
        output.Flush();
    }

    // The reachability probe is taken here rather than inside the servers: those stay the byte-deciders
    // tests/servcheck drives, and a datagram that got this far has already answered the only question it
    // was sent to ask. The line is the evidence, printed where the delivery is observed.
    private static bool TookProbe(LanProbe probe, UdpReceiveResult request)
    {
        if (!probe.Consume(request.Buffer, Host.ToBigEndian(request.RemoteEndPoint.Address))) return false;
        Console.WriteLine($"[Router] {probe.Name} probe token {probe.Token} delivered from {request.RemoteEndPoint}");
        return true;
    }

    // The transport DnsServer asks for: UDP first, and TCP for the retry a truncated answer calls for.
    // A two-octet length prefix is what RFC 1035 §4.2.2 puts in front of a message on a TCP connection,
    // which is why that path cannot just read whatever arrives.
    //
    // One socket serves every query, and the answers are told apart by the transaction id this server put
    // on the query - so the receive half runs on its own loop rather than inside a caller's send. Measured
    // on this host, 192.168.1.1 answers an A query in milliseconds but never answers an SVCB/HTTPS one for
    // some names; with a synchronous receive under DnsServer's lock that stall held every other client's
    // question for the whole four seconds, which is the "LAN gets no DNS while this host is fine" shape.
    //
    // The table is here for one reason: to say, at the moment a query goes unanswered, whether this
    // socket's own port is currently somebody's mapped port. `netsh int ipv4 show dynamicport udp` gives
    // this host 49152-65535 for OS-chosen local ports and NatTable hands out mapped ports from the same
    // span, so the two ranges can meet; REQ-1 (RFC 4787) then makes the mapped port alone the reverse key.
    public sealed class UpstreamResolver
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(4);

        private readonly UdpClient _socket;
        private readonly IPEndPoint _endpoint;
        private readonly NatTable _table;
        private readonly Dictionary<ushort, TaskCompletionSource<byte[]?>> _pending = new();
        private readonly object _pendingGate = new();
        private readonly uint _upstream;
        private readonly ushort _ownPort;
        private readonly Task _receiver;

        public UpstreamResolver(UdpClient socket, IPEndPoint endpoint, NatTable table)
        {
            _socket = socket;
            _endpoint = endpoint;
            _table = table;
            _upstream = Host.ToBigEndian(endpoint.Address);
            socket.Connect(endpoint);
            _ownPort = (ushort)((IPEndPoint)socket.Client.LocalEndPoint!).Port;
            _receiver = Task.Run(ReceiveLoop);
        }

        public byte[]? Ask(byte[] message, bool useTcp)
        {
            if (useTcp) return QueryOverTcp(_endpoint, message);

            var id = BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(0, 2));
            var answer = new TaskCompletionSource<byte[]?>(TaskCreationOptions.RunContinuationsAsynchronously);
            lock (_pendingGate)
            {
                // 65536 questions would have to be in flight for an id to come round again; refusing the
                // newcomer rather than replacing the waiter keeps one id naming one question.
                if (_pending.ContainsKey(id)) return null;
                _pending[id] = answer;
            }

            try
            {
                _socket.Send(message, message.Length);
                if (answer.Task.Wait(Timeout)) return answer.Task.Result;

                Console.WriteLine($"[Router] upstream DNS {NatTable.FormatAddress(_upstream)} failed: " +
                                  $"no answer within {Timeout.TotalSeconds:0}s");
                AnswerVerdict();
                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Router] upstream DNS {NatTable.FormatAddress(_upstream)} failed: {ex.Message}");
                AnswerVerdict();
                return null;
            }
            finally
            {
                lock (_pendingGate) _pending.Remove(id);
            }
        }

        private void AnswerVerdict() =>
            Console.WriteLine(_table.IsMappedPort(17, _ownPort)
                ? $"[Router]   UDP {_ownPort} is this socket's own port and the table has it mapped, so the answer " +
                  "was translated to a LAN client's flow instead of delivered here"
                : $"[Router]   UDP {_ownPort}, this socket's own port, is not mapped: the table did not take this answer");

        private async Task ReceiveLoop()
        {
            while (true)
            {
                UdpReceiveResult answer;
                try
                {
                    answer = await _socket.ReceiveAsync().ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is ObjectDisposedException or SocketException)
                {
                    // The run is ending. A caller still inside its wait is released here rather than being
                    // held to its own timeout, so shutdown does not add four seconds per waiting query.
                    if (ex is SocketException failure)
                        Console.WriteLine($"[Router] upstream DNS receive failed: {failure.Message}");
                    break;
                }
                if (answer.Buffer.Length < DnsFormat.HeaderLength) continue;
                var id = BinaryPrimitives.ReadUInt16BigEndian(answer.Buffer);
                TaskCompletionSource<byte[]?>? waiting;
                lock (_pendingGate) _pending.TryGetValue(id, out waiting);
                // An answer to a query that already timed out has no waiter left, and is dropped here.
                waiting?.TrySetResult(answer.Buffer);
            }

            lock (_pendingGate)
                foreach (var waiting in _pending.Values) waiting.TrySetResult(null);
        }
    }

    // A resolver keeps one socket and one receive loop for the whole run, so the returned delegate is the
    // same object for every caller DnsServer hands it to.
    public static Func<byte[], bool, byte[]?> Upstream(uint upstream, UdpClient socket, NatTable table) =>
        new UpstreamResolver(socket, new IPEndPoint(Host.ToIpAddress(upstream), DnsPorts.ServerPort), table).Ask;

    private static byte[]? QueryOverTcp(IPEndPoint endpoint, byte[] message)
    {
        using var client = new TcpClient();
        client.Connect(endpoint);
        client.ReceiveTimeout = 4000;
        using var stream = client.GetStream();

        var framed = new byte[message.Length + 2];
        BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)message.Length);
        message.CopyTo(framed.AsSpan(2));
        stream.Write(framed);

        var prefix = new byte[2];
        if (!ReadExactly(stream, prefix)) return null;
        var body = new byte[BinaryPrimitives.ReadUInt16BigEndian(prefix)];
        return ReadExactly(stream, body) ? body : null;
    }

    private static bool ReadExactly(Stream stream, byte[] buffer)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var got = stream.Read(buffer, read, buffer.Length - read);
            if (got <= 0) return false;
            read += got;
        }
        return true;
    }

    // The uint form used throughout this project is the four octets read big-endian, so 192.168.2.1 is
    // 0xC0A80201; Host owns both directions of the conversion to it.
}

public static class DnsPorts
{
    // RFC 1035 §4.2.1: "Messages sent using UDP user server port 53 (decimal).", and §4.2.2: "Messages
    // sent over TCP connections use server port 53 (decimal)."
    public const ushort ServerPort = 53;
}
