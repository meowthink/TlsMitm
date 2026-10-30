using System.Net;
using TlsMitm;

// Offline judgement for the redirector's flow table: no driver, no admin, no sockets. Each case hands
// the table the keys a packet would carry and asserts what comes back - which token, which client, and
// whether a second connection was merged into the first one's state.
var failures = new List<string>();
var notes = new List<string>();
var now = new DateTime(2026, 10, 30, 12, 0, 0, DateTimeKind.Utc);
var table = new FlowTable(() => now);

// The relay port the proxy listens on. A token has to stay out of its reach, because a packet whose
// source port is the relay port is what names the reply leg.
const int RelayPort = 8443;

static uint V4(string text) => BitConverter.ToUInt32(IPAddress.Parse(text).GetAddressBytes());
static (ulong Hi, ulong Lo) V6(string text)
{
    var bytes = IPAddress.Parse(text).GetAddressBytes();
    return (BitConverter.ToUInt64(bytes.AsSpan(0, 8)), BitConverter.ToUInt64(bytes.AsSpan(8, 8)));
}
static FlowKey Key(string client, int clientPort, string server, int serverPort)
{
    var (hi, lo) = V6(client);
    var (shi, slo) = V6(server);
    return FlowTable.KeyV6(hi, lo, (ushort)clientPort, shi, slo, (ushort)serverPort);
}
static FlowKey Key4(uint client, int clientPort, uint server, int serverPort) =>
    FlowTable.KeyV4(client, (ushort)clientPort, server, (ushort)serverPort);

var lanClient = V4("192.0.2.10");
var lanClient2 = V4("192.0.2.11");
var host = V4("192.0.2.1");
var server = V4("198.51.100.7");

// --- Two LAN clients that picked the same ephemeral port to the same server -----------------------
// This is the case that used to be fatal rather than merely awkward: both flows carried the same
// (client port, server address), the second SYN replaced the first one's state, and the reply leg
// restored the destination address out of that one state - so the first client's TLS records were
// addressed to the second client. RFC 793 §3.1 identifies a connection by all four fields, so the
// table has to see all four.
var first = table.Open(Key4(lanClient, 50000, server, 443), intercept: true);
var second = table.Open(Key4(lanClient2, 50000, server, 443), intercept: true);
Expect(first.Token != second.Token && first.Token != 0 && second.Token != 0,
    $"two clients on one port get two tokens, got {first.Token} and {second.Token}");
Expect(table.Count == 2, $"both states are live, got {table.Count}");
Expect(table.ByToken(first.Token)!.ClientRaw == lanClient,
    $"the first token answers to the first client, got {table.ByToken(first.Token)!.ClientAddr}");
Expect(table.ByToken(second.Token)!.ClientRaw == lanClient2,
    $"the second token answers to the second client, got {table.ByToken(second.Token)!.ClientAddr}");
Expect(table.ByToken(first.Token)!.Key.ClientPort == 50000 && table.ByToken(first.Token)!.OrigDstPort == 443,
    "each state still names its own client port and destination port");

// --- One client, same port, the same server on a second port --------------------------------------
// The shape that collides with no LAN involved: a local socket may reuse its ephemeral port for a
// second destination port on one address, and the server port is the only field that tells them apart.
var https = table.Open(Key4(host, 51000, server, 443), intercept: true);
var alt = table.Open(Key4(host, 51000, server, 8443), intercept: true);
Expect(https.Token != alt.Token, $"one client's two server ports get two tokens, got {https.Token} and {alt.Token}");
Expect(https.OrigDstPort == 443 && alt.OrigDstPort == 8443,
    $"each keeps its own destination port, got {https.OrigDstPort} and {alt.OrigDstPort}");
notes.Add($"tokens handed out: {first.Token}, {second.Token}, {https.Token}, {alt.Token}");

// --- A retransmitted SYN is the same connection -----------------------------------------------------
var retransmit = table.Open(Key4(lanClient, 50000, server, 443), intercept: true);
Expect(retransmit.Token == first.Token, $"a repeated SYN keeps its token, got {retransmit.Token} vs {first.Token}");
Expect(table.Count == 4, $"a repeated SYN opens no second flow, got {table.Count}");

// --- The token is only ever an ephemeral one, never the relay port ---------------------------------
foreach (var token in new[] { first.Token, second.Token, https.Token, alt.Token })
{
    Expect(token is >= 49152 and <= 65535, $"token {token} is inside RFC 6335 §5.2.1's Dynamic range");
    Expect(token != RelayPort, $"token {token} never equals the relay port, which names the reply leg");
}

// --- A packet whose SYN was never seen has no state, and a bypassed flow still has one --------------
Expect(table.Follow(Key4(lanClient, 52000, server, 443)) == null, "an unknown connection is a miss");
var scopePass = table.Open(Key4(host, 53000, server, 25), intercept: false);
Expect(scopePass.Bypassed && scopePass.Token == 0, "a flow the scope excluded takes no token");
Expect(table.Count == 4, $"a bypassed flow holds no token slot, got {table.Count}");
Expect(table.Follow(Key4(host, 53000, server, 25))!.Bypassed, "its later packets are still recognised, not reported as misses");

// --- v4 and v6 carrying the same numbers are not one connection -------------------------------------
var v6 = table.Open(Key("2001:db8::1", 50000, "2001:db8::7", 443), intercept: true);
Expect(v6.Token != first.Token, $"a v6 flow on the same port pair gets its own token, got {v6.Token}");
Expect(v6.ClientAddr.ToString() == "2001:db8::1" && v6.OrigDstAddr.ToString() == "2001:db8::7",
    $"the v6 addresses survive, got {v6.ClientAddr} and {v6.OrigDstAddr}");

// --- Ageing: an idle flow loses its token, and the token is not left pointing at nothing ------------
var live = table.Open(Key4(lanClient, 54000, server, 443), intercept: true);
var closing = table.Open(Key4(lanClient2, 55000, server, 443), intercept: true);
closing.Closing = true;

// Everything opened above was last seen five minutes ago except these two, which carry a packet at the
// instant the sweep runs.
now += TimeSpan.FromMinutes(5) + TimeSpan.FromSeconds(1);
live.LastSeen = now;
closing.LastSeen = now;
var dropped = table.Sweep();
Expect(dropped.Any(s => s.Token == first.Token), "an idle flow is dropped");
Expect(table.ByToken(first.Token) == null, "its token names nothing afterwards");
Expect(table.Follow(Key4(lanClient, 50000, server, 443)) == null,
    "and its four fields are forgotten too, so a later packet is a miss rather than a stale rewrite");
Expect(!dropped.Any(s => s.Token == live.Token), "a flow that was used on the sweep's instant stays");
Expect(!dropped.Any(s => s.Token == closing.Token), "a closed flow is judged by ten seconds, not by five minutes");

var reuse = table.Open(Key4(host, 41000, server, 443), intercept: true);
Expect(reuse.Token != 0, "a freed token is handed to the next flow");
notes.Add($"after the sweep: kept {table.Count}, dropped {dropped.Count}");

// A closed flow that says nothing more for ten seconds is gone, while a quiet one still has four.
now += TimeSpan.FromSeconds(11);
dropped = table.Sweep();
Expect(dropped.Any(s => s.Token == closing.Token), "a flow past its FIN/RST goes in ten seconds");
Expect(!dropped.Any(s => s.Token == live.Token), "a flow with no FIN/RST is not swept on the closing clock");

// --- A session's own end, not silence, decides when its flow is over -------------------------------
// The proxy claims a flow when it accepts the socket and releases it when the relay returns. In between,
// a connection that carries nothing for ten minutes is still the connection the client believes it has:
// forgetting it hands the next packet to a server that never saw that connection, and the answer to that
// is a reset. The release itself then hands the flow to the closing clock, which is sized for exactly
// the few packets a connection sends while it ends.
var sessionNow = new DateTime(2026, 10, 30, 12, 0, 0, DateTimeKind.Utc);
var sessions = new FlowTable(() => sessionNow);
var quiet = sessions.Open(Key4(lanClient, 60000, server, 443), intercept: true);
quiet.Session = true;
sessionNow += TimeSpan.FromMinutes(30);
Expect(!sessions.Sweep().Any(s => s.Token == quiet.Token), "a session idle for half an hour keeps its token");
Expect(sessions.ByToken(quiet.Token) != null, "and its reply leg still resolves after the silence");
Expect(sessions.Follow(Key4(lanClient, 60000, server, 443)) != null, "and its own packets still find the state");

var claimedToken = quiet.Token;
sessions.EndSession(claimedToken);
// A release is not an erasure: the FIN the proxy sends as its own session ends is still in flight behind
// it, and answering that with a miss is what stops the client ever seeing our close.
Expect(sessions.Count == 1, "the release leaves the flow held, for the packets that trail it");
Expect(sessions.ByToken(claimedToken) != null, "so the reply leg of the close still resolves");
Expect(sessions.Follow(Key4(lanClient, 60000, server, 443)) != null, "and so do the flow's own four fields");
sessionNow += TimeSpan.FromSeconds(1);
Expect(!sessions.Sweep().Any(s => s.Token == claimedToken), "one second past the release the closing clock has not run");
sessionNow += TimeSpan.FromSeconds(10);
Expect(sessions.Sweep().Any(s => s.Token == claimedToken), "ten seconds past it the flow is gone");
Expect(sessions.Count == 0, $"and nothing is held after the closing window, got {sessions.Count}");

var again = sessions.Open(Key4(lanClient, 60000, server, 443), intercept: true);
Expect(again.Token != claimedToken && again.Token != 0,
    $"a re-SYN past the closing window is named by its own token, got {again.Token} after {claimedToken}");

// A FIN on the forward leg does not outrank the session that owns the flow: the relay is what ends it.
var reset = sessions.Open(Key4(lanClient2, 60000, server, 443), intercept: true);
reset.Session = true;
reset.Closing = true;
sessionNow += TimeSpan.FromSeconds(30);
Expect(!sessions.Sweep().Any(s => s.Token == reset.Token), "a session that saw a FIN still waits for its own end");

// The backstop for a session that never reports its end, so that one stuck flow cannot hold a token for
// the whole run.
sessionNow += TimeSpan.FromHours(2) + TimeSpan.FromSeconds(1);
Expect(sessions.Sweep().Any(s => s.Token == reset.Token), "two hours of silence does end a session's claim");

// --- The pool gives up rather than sharing a token ---------------------------------------------------
// Every state that cannot be named has to be passed through instead: a second flow on the same token
// is the cross-talk this table exists to prevent.
var pool = new FlowTable(() => now);
var opened = 0;
for (var i = 0; i < 65535 - 49152 + 1; i++)
{
    var state = pool.Open(Key4(host, 40000 + i, server, 443), intercept: true);
    if (!state.Bypassed) opened++;
}
Expect(opened == 65535 - 49152 + 1, $"every slot of the pool was taken, got {opened}");
var overflow = pool.Open(Key4(host, 30000, server, 443), intercept: true);
Expect(overflow.Bypassed && pool.Refused == 1, $"the flow past the pool is refused once, got bypassed={overflow.Bypassed} refused={pool.Refused}");
Expect(pool.Count == 65535 - 49152 + 1, $"a refusal consumes no slot, got {pool.Count}");

if (failures.Count > 0)
{
    Console.WriteLine($"[flowcheck] FAIL ({failures.Count})");
    failures.ForEach(Console.WriteLine);
    return 1;
}
notes.ForEach(n => Console.WriteLine($"[flowcheck] note: {n}"));
Console.WriteLine("[flowcheck] PASS - two clients on one port, one client on two ports, retransmit, " +
                  "bypass, family, ageing, session release and pool exhaustion");
return 0;

void Expect(bool condition, string what)
{
    if (!condition) failures.Add(what);
    Console.WriteLine($"{(condition ? "ok  " : "FAIL")} {what}");
}
