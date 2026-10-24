namespace TlsMitm;

/// <summary>
/// An ECH ClientHello keeps the origin out of reach. RFC 9849 gives a conformant client no way to carry
/// on: when the server rejects ECH it authenticates the public name (§6.1.7, which adds that the TLS
/// implementation MUST NOT report such a connection as successful to the application), then MUST abort
/// with an "ech_required" alert before sending any application data and MUST NOT treat the rejection as
/// a secure signal to disable ECH; the sanctioned next step is a retry on a new connection using the
/// server's retry_configs (§6.1.6). So nothing in the RFC makes this probe pay off, and what it does
/// rest on is measured: Edge 155, handed a leaf for the public name it had offered, either retried with
/// no ECH extension at all - which carries the SNI we want - or simply kept using the terminated
/// session. Either outcome proves the probe worked on that host, and a proven host is then terminated
/// without any window for a while. A host that shows neither returns to blind relay, because an
/// experiment must not leave a site failing.
/// </summary>
public sealed class EchDowngrade
{
    private static readonly TimeSpan RetryWindow = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan BlindFor = TimeSpan.FromMinutes(10);

    // Long enough to cover a burst of connections from one process, short enough that a client which
    // is upgraded in place gets re-probed instead of trusted from a stale measurement.
    private static readonly TimeSpan ProvenFor = TimeSpan.FromMinutes(10);

    private readonly object _gate = new();
    private readonly Dictionary<(int Pid, string Host), (long ProbedAt, long BlindUntil, long ProvenAt)> _hosts = new();
    private readonly Func<long> _now;

    /// <param name="now">
    /// Milliseconds since an arbitrary origin, the same clock as <see cref="Environment.TickCount64"/>.
    /// A caller that needs to move through the retry window supplies its own instead of waiting for it.
    /// </param>
    public EchDowngrade(Func<long>? now = null)
    {
        _now = now ?? (() => Environment.TickCount64);
    }

    /// <summary>
    /// Records that a hello was seen and answers whether an ECH one should be terminated here rather
    /// than blind-relayed. Plaintext hellos are what the retry looks like, so they are reported too.
    /// </summary>
    public bool Terminate(int pid, string host, bool echOffered)
    {
        lock (_gate)
        {
            var key = (pid, host);
            var now = _now();
            _hosts.TryGetValue(key, out var state);

            if (state.BlindUntil > now)
            {
                if (echOffered)
                    Console.WriteLine($"[ECH] {host}: blind relay - the last probe drew no data and no plaintext retry, " +
                        $"probing again in {(state.BlindUntil - now) / 1000}s");
                return false;
            }

            // A measured success covers the host for a while: this client keeps the terminated
            // connection, so it never sends the plaintext hello a window waits for, and one probe that
            // landed while it was closing speculative sockets must not flip a host that has already
            // streamed megabytes back to blind relay.
            if (state.ProvenAt > 0 && now - state.ProvenAt < (long)ProvenFor.TotalMilliseconds)
            {
                if (!echOffered) return false;
                Console.WriteLine($"[ECH] {host}: terminating - this client kept a terminated session " +
                    $"{(now - state.ProvenAt) / 1000}s ago");
                return true;
            }

            if (state.ProbedAt > 0)
            {
                if (!echOffered)
                {
                    _hosts.Remove(key);
                    Console.WriteLine($"[ECH] {host}: retry carries no ECH - the client disabled it, plaintext from here");
                    return false;
                }

                if (now - state.ProbedAt > (long)RetryWindow.TotalMilliseconds)
                {
                    _hosts[key] = (0, now + (long)BlindFor.TotalMilliseconds, state.ProvenAt);
                    Console.WriteLine($"[ECH] {host}: no data and no plaintext retry within {RetryWindow.TotalSeconds:0}s - " +
                        $"blind relay for {BlindFor.TotalMinutes:0} min");
                    return false;
                }
            }

            if (!echOffered) return false;

            // Parallel ECH connections must not extend the window, so the earliest probe is kept.
            if (state.ProbedAt == 0)
                _hosts[key] = (now, 0, state.ProvenAt);
            Console.WriteLine($"[ECH] {host}: terminating - public name authenticated, ECH not accepted " +
                "(a §6.1.6 retry without ECH, or application bytes on this session, is what proves it worked)");
            return true;
        }
    }

    /// <summary>
    /// Records that a terminated session carried application data, which proves the probe worked
    /// without a plaintext retry and moves the host onto the proven path. A blind entry is left alone:
    /// those hosts are relayed untouched, so a terminated session of theirs cannot exist.
    /// </summary>
    public void ObservedData(int pid, string host)
    {
        lock (_gate)
        {
            if (_hosts.TryGetValue((pid, host), out var state) && state.BlindUntil == 0)
            {
                _hosts[(pid, host)] = (0, 0, _now());
                Console.WriteLine($"[ECH] {host}: terminated session carried data - ECH termination works for this client");
            }
        }
    }
}
