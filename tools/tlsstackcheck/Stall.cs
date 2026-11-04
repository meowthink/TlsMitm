using System.Net;
using System.Net.Sockets;

/// <summary>
/// A loopback listener that accepts one connection and then reads and writes nothing, so a handshake
/// against it stops at the first round trip. Option validation happens before any byte leaves, which is
/// what makes it enough for a knob probe.
/// </summary>
internal sealed class Stall : IDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new(TimeSpan.FromSeconds(5));

    public Stall()
    {
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _ = AcceptAndForget();
    }

    public int Port { get; }
    public CancellationToken Token => _cts.Token;

    private async Task AcceptAndForget()
    {
        try
        {
            using var client = await _listener.AcceptTcpClientAsync(_cts.Token);
            await Task.Delay(Timeout.Infinite, _cts.Token);
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException) { }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _listener.Stop();
        _cts.Dispose();
    }
}
