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
/// without any window for a while.
///
/// §6.1.7 is also what convicts a probe. A client that holds a real configuration cannot turn the
/// session into a working one, and the captures show a refusal arriving as an alert in place of
/// Finished, so the client leg's own outcome is the only evidence against a host. Silence is not
/// evidence: §6.2.1 has a client with no configuration send GREASE ECH, and that is what Chrome and
/// Edge send for a host that publishes no ech SvcParam (measured: cn.bing.com, sixteen hellos, sixteen
/// different config_id bytes, no HTTPS RR in its CNAME chain). Such a client finishes the terminated
/// handshake and then sits idle, so a quiet connection says nothing about whether termination worked -
/// scoring it as failure is what used to blind a host around every page load. Only a client leg that
/// fails sends a host back to blind relay, because an experiment must not leave a site failing.
/// </summary>
public sealed class EchDowngrade
{
    private static readonly TimeSpan BlindFor = TimeSpan.FromMinutes(10);

    // Long enough to cover a burst of connections from one process, short enough that a client which
    // is upgraded in place gets re-probed instead of trusted from a stale measurement.
    private static readonly TimeSpan ProvenFor = TimeSpan.FromMinutes(10);

    private readonly object _gate = new();
    private readonly Dictionary<(int Pid, string Host), (long BlindUntil, long ProvenAt, bool Failed)> _hosts = new();
    private readonly Func<long> _now;

    /// <param name="now">
    /// Milliseconds since an arbitrary origin, the same clock as <see cref="Environment.TickCount64"/>.
    /// A caller that needs to move through a window supplies its own instead of waiting for it.
    /// </param>
    public EchDowngrade(Func<long>? now = null)
    {
        _now = now ?? (() => Environment.TickCount64);
    }

    /// <summary>
    /// Records that a hello was seen and answers whether an ECH one should be terminated here rather
    /// than blind-relayed. Plaintext hellos are reported too: a client that drops ECH after a failed
    /// probe needs no decision, and the failure is forgotten with it.
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
                    Console.WriteLine($"[ECH] {host}: blind relay - the last client leg failed, " +
                        $"probing again in {(state.BlindUntil - now) / 1000}s");
                return false;
            }

            if (state.Failed)
            {
                if (!echOffered)
                {
                    _hosts.Remove(key);
                    Console.WriteLine($"[ECH] {host}: retry carries no ECH - the client disabled it, plaintext from here");
                    return false;
                }

                _hosts[key] = (now + (long)BlindFor.TotalMilliseconds, state.ProvenAt, false);
                Console.WriteLine($"[ECH] {host}: the last terminated session's client leg failed - " +
                    $"blind relay for {BlindFor.TotalMinutes:0} min");
                return false;
            }

            if (!echOffered) return false;

            // A measured success covers the host for a while: this client keeps the terminated
            // connection, so it never sends the plaintext hello a window waits for, and one probe that
            // landed while it was closing speculative sockets must not flip a host that has already
            // streamed megabytes back to blind relay.
            if (state.ProvenAt > 0 && now - state.ProvenAt < (long)ProvenFor.TotalMilliseconds)
            {
                Console.WriteLine($"[ECH] {host}: terminating - this client kept a terminated session " +
                    $"{(now - state.ProvenAt) / 1000}s ago");
                return true;
            }

            Console.WriteLine($"[ECH] {host}: terminating - public name authenticated, ECH not accepted " +
                "(a §6.1.6 retry without ECH, or application bytes on this session, is what proves it worked)");
            return true;
        }
    }

    /// <summary>
    /// Records that the client leg of a terminated session failed. That is the §6.1.7 refusal shape -
    /// the client will not turn the public-name session into a working one - so it is what moves the
    /// host to blind relay. A blind entry and a recently proven host are left alone: the first is
    /// already relayed, and the second has carried application data this session, which a real
    /// configuration could not have done.
    /// </summary>
    public void ProbeFailed(int pid, string host)
    {
        lock (_gate)
        {
            var key = (pid, host);
            var now = _now();
            _hosts.TryGetValue(key, out var state);

            if (state.BlindUntil > now) return;
            if (state.ProvenAt > 0 && now - state.ProvenAt < (long)ProvenFor.TotalMilliseconds)
            {
                Console.WriteLine($"[ECH] {host}: client leg failed, but a terminated session carried data " +
                    $"{(now - state.ProvenAt) / 1000}s ago - staying on termination");
                return;
            }

            _hosts[key] = (0, state.ProvenAt, true);
            Console.WriteLine($"[ECH] {host}: client leg failed after termination - the next ECH hello goes blind");
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
            var key = (pid, host);
            var now = _now();
            if (_hosts.TryGetValue(key, out var state) && state.BlindUntil > now) return;

            _hosts[key] = (0, now, false);
            Console.WriteLine($"[ECH] {host}: terminated session carried data - ECH termination works for this client");
        }
    }
}
