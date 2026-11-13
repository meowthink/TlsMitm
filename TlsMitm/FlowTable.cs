using System.Collections.Concurrent;
using System.Net;

namespace TlsMitm;

/// The identity of one TCP connection as its own packets carry it before any rewrite: RFC 793 §3.1
/// names the four fields that identify a connection, and anything narrower merges two connections into
/// one state. Both addresses are held as the header's own 64-bit halves, so a v4 address sits in
/// <c>ClientHi</c> or <c>ServerHi</c> with its <c>Lo</c> half zero and the family tells them apart.
internal readonly record struct FlowKey(
    bool V6,
    ulong ClientHi, ulong ClientLo, ushort ClientPort,
    ulong ServerHi, ulong ServerLo, ushort ServerPort);

/// One intercepted connection. Everything the rewrite has to remember is in the key it was opened
/// with, so the key is the only stored field besides the token and the ageing.
internal sealed class FlowState
{
    public required FlowKey Key { get; init; }

    // The value the forward leg writes into the packet's source port, and the only field of an
    // accepted socket that no two flows in this table can share. Zero means none was given.
    public ushort Token { get; set; }

    public DateTime LastSeen { get; set; } = DateTime.UtcNow;
    public int RevCount;
    public bool Closing;

    // Set when a proxy session takes the flow. From that point the session's own end, not silence, is
    // what closes it: a connection that carries no bytes for ten minutes is still a connection, and
    // forgetting it would answer its next packet with a reset.
    public bool Session;

    // Which claim of this flow is the current one. A fast reconnect can reuse the four fields - and so the
    // token - while the previous session is still draining; each claim takes the next number, and a release
    // only ends the claim that carries its own number, so the old session cannot close the new one's flow.
    public int Generation;

    // A flow nothing downstream may rewrite: one the process scope excluded, or one that found the
    // token pool full. It stays known so its later packets are not reported as a forwarding miss.
    public bool Bypassed { get; set; }

    public IPAddress ClientAddr => Address(Key.V6, Key.ClientHi, Key.ClientLo);
    public int ClientPort => Key.ClientPort;
    public IPAddress OrigDstAddr => Address(Key.V6, Key.ServerHi, Key.ServerLo);
    public int OrigDstPort => Key.ServerPort;
    public uint ClientRaw => unchecked((uint)Key.ClientHi);
    public uint OrigDstRaw => unchecked((uint)Key.ServerHi);

    private static IPAddress Address(bool v6, ulong hi, ulong lo) => v6
        ? new IPAddress(RawV6Bytes(hi, lo))
        : new IPAddress(BitConverter.GetBytes(unchecked((uint)hi)));

    internal static byte[] RawV6Bytes(ulong hi, ulong lo)
    {
        var bytes = new byte[16];
        BitConverter.TryWriteBytes(bytes.AsSpan(0, 8), hi);
        BitConverter.TryWriteBytes(bytes.AsSpan(8, 8), lo);
        return bytes;
    }
}

/// The table behind the rewrite: it decides which connection a packet belongs to and what token that
/// connection is carried under. Kept free of WinDivert and of the system clock, so a collision between
/// two clients, a retransmitted SYN or an expired entry can be judged offline on keys alone.
internal sealed class FlowTable
{
    // RFC 6335 §5.2.1's Dynamic range. The relay port sits below it, which is what keeps a token from
    // ever being mistaken for the reply leg: a packet whose source port is the relay port is a reply.
    private const int TokenBase = 49152;
    private const int TokenSpan = 65535 - TokenBase + 1;

    private static readonly TimeSpan IdleLimit = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan ClosingLimit = TimeSpan.FromSeconds(10);

    // Only the backstop for a session that never reported its end - the process would have to die inside
    // one, which frees every token anyway. It is set far past any live connection's quiet period so that
    // it never decides for a session that is merely idle.
    private static readonly TimeSpan SessionLimit = TimeSpan.FromHours(2);

    private readonly ConcurrentDictionary<FlowKey, FlowState> _flows = new();
    private readonly ConcurrentDictionary<ushort, FlowState> _byToken = new();
    private readonly Func<DateTime> _clock;
    private int _nextToken;
    private int _refused;

    // Every writer of a state's ageing takes this, and so does the sweep's expiry test together with its
    // removal. Open revives the *same* object through GetOrAdd, so comparing identities at removal would
    // still drop a flow that a packet or a repeated SYN had just refreshed: what changes is LastSeen, not
    // the reference. The test and the removal therefore have to be one step against every writer.
    private readonly object _gate = new();

    public FlowTable(Func<DateTime>? clock = null) => _clock = clock ?? (() => DateTime.UtcNow);

    // The two ways a packet's header fields name a connection, kept here so that which fields count is
    // judged with the table rather than left to each caller.
    public static FlowKey KeyV4(uint clientAddr, ushort clientPort, uint serverAddr, ushort serverPort) =>
        new(false, clientAddr, 0, clientPort, serverAddr, 0, serverPort);

    public static FlowKey KeyV6(ulong clientHi, ulong clientLo, ushort clientPort,
        ulong serverHi, ulong serverLo, ushort serverPort) =>
        new(true, clientHi, clientLo, clientPort, serverHi, serverLo, serverPort);

    public int Count => _byToken.Count;

    // Flows the pool could not name, which went unintercepted rather than sharing a token.
    public int Refused => Volatile.Read(ref _refused);

    /// The state a SYN opens. A retransmitted SYN, or any repeat of the same four fields, comes back
    /// with the token the first one was given, so the two never become separate states.
    public FlowState Open(FlowKey key, bool intercept)
    {
        lock (_gate)
        {
            var state = new FlowState { Key = key, LastSeen = _clock() };
            var live = _flows.GetOrAdd(key, state);
            if (!ReferenceEquals(live, state))
            {
                live.LastSeen = _clock();
                live.Closing = false;
                return live;
            }
            if (!intercept || !TryAllocate(live)) live.Bypassed = true;
            return live;
        }
    }

    /// A packet of a known connection keeps it alive. The table owns the ageing so that this refresh and
    /// the sweep's expiry test are one step, and so the offline judge drives it with the same clock.
    public void Touch(FlowState state)
    {
        lock (_gate) state.LastSeen = _clock();
    }

    /// A FIN/RST seen on either leg. Only the flag: the closing clock runs from the last packet, which is
    /// what the peer's outstanding ACKs are counted against.
    public void MarkClosing(FlowState state)
    {
        lock (_gate) state.Closing = true;
    }

    /// A proxy session has taken the flow, so its own end rather than silence decides when it goes. Returns
    /// the claim's generation: a reconnect that reuses the token takes the next one, and only a release
    /// carrying that same number may end it.
    public int ClaimSession(FlowState state)
    {
        lock (_gate)
        {
            state.Session = true;
            return ++state.Generation;
        }
    }

    /// The state a later packet of a known connection finds, or null when no SYN of that connection has
    /// been seen - the one case a packet is released unrouted.
    public FlowState? Follow(FlowKey key) => _flows.TryGetValue(key, out var state) ? state : null;

    public FlowState? ByToken(ushort token) => _byToken.TryGetValue(token, out var state) ? state : null;

    /// A token no live flow holds, for the inbound probe to carry as its peer's port. That port is what
    /// the relay's lookup is keyed on, so a real flow holding it would answer the probe with its own
    /// session. Zero when the pool is full.
    public ushort FreeToken()
    {
        for (var attempt = 0; attempt < TokenSpan; attempt++)
        {
            var token = (ushort)(TokenBase + (uint)Interlocked.Increment(ref _nextToken) % TokenSpan);
            if (!_byToken.ContainsKey(token)) return token;
        }
        return 0;
    }

    /// Hand a finished session's flow to the closing clock. Not a deletion: the session's own FIN and its
    /// ACKs are still in flight behind it, and the rewrite has to translate those too. The token stays
    /// claimed for that window, which is what the clock is sized for. A release whose generation is not the
    /// current one belongs to a superseded claim - a reconnect already took the token - and ends nothing.
    public void EndSession(ushort token, int generation)
    {
        lock (_gate)
        {
            if (!_byToken.TryGetValue(token, out var state)) return;
            if (state.Generation != generation) return;
            state.Session = false;
            state.Closing = true;
            state.LastSeen = _clock();
        }
    }

    /// Drop the states nobody has used for a while, freeing their tokens. Returns what went, so the
    /// caller can report it.
    public List<FlowState> Sweep()
    {
        var now = _clock();
        var dropped = new List<FlowState>();
        foreach (var state in _byToken.Values)
        {
            lock (_gate)
            {
                var limit = state.Session ? SessionLimit : state.Closing ? ClosingLimit : IdleLimit;
                if (now - state.LastSeen < limit) continue;
                if (_byToken.TryRemove(state.Token, out _) && _flows.TryRemove(state.Key, out _)) dropped.Add(state);
            }
        }
        foreach (var state in _flows.Values)
        {
            lock (_gate)
            {
                // A bypassed state holds no token, so the pass above never reached it.
                if (!state.Bypassed || now - state.LastSeen < IdleLimit) continue;
                if (_flows.TryRemove(state.Key, out _)) dropped.Add(state);
            }
        }
        return dropped;
    }

    private bool TryAllocate(FlowState state)
    {
        if (_byToken.Count >= TokenSpan)
        {
            Interlocked.Increment(ref _refused);
            return false;
        }
        for (var attempt = 0; attempt < TokenSpan; attempt++)
        {
            var token = (ushort)(TokenBase + (uint)Interlocked.Increment(ref _nextToken) % TokenSpan);
            if (_byToken.TryAdd(token, state))
            {
                state.Token = token;
                return true;
            }
        }
        Interlocked.Increment(ref _refused);
        return false;
    }
}
