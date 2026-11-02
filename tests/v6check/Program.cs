using System.Buffers.Binary;
using System.Net;
using Router;

// Offline judgement for the router's IPv6 side: the DHCPv6 prefix-delegation client and the Router
// Advertisement that hands the delegated prefix to the LAN. No socket, no admin, no driver, and no clock
// of its own. Every datagram fed in here is laid out octet by octet in this file, never through the
// product's builder, so an encoder and a parser that share a mistake cannot agree with each other.

var failures = new List<string>();
var notes = new List<string>();

void Expect(bool ok, string what)
{
    if (ok) notes.Add($"ok {what}");
    else failures.Add(what);
}

// Locally administered, not a manufacturer's block: RFC 7042 §2 makes the second bit of the first octet
// the universal/local bit, and set means the address was not globally assigned, so no fixture here can
// double as some real interface's identity.
var mac = new byte[] { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
var duid = Dhcp6.DuidLl(mac);
var serverDuid = new byte[] { 0x00, 0x03, 0x00, 0x01, 0x02, 0x66, 0x77, 0x88, 0x99, 0xaa };
var otherServerDuid = new byte[] { 0x00, 0x03, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
// fe80:: with the interface identifier written in, and RFC 4291 Appendix says that identifier is the
// MAC's EUI-64 form with the universal/local bit inverted - so this address and the server's DUID
// describe one machine, whichever way round a reader checks them.
var serverA = IPAddress.Parse("fe80::66:77ff:fe88:99aa");
var serverB = IPAddress.Parse("fe80::1");
const uint Iaid = 0x01020304;
const string F18 = "2001:db8:1:f18::";
const string F20 = "2001:db8:1:f20::";
var t0 = new DateTime(2026, 10, 31, 9, 0, 0, DateTimeKind.Utc);
var half = TimeSpan.FromMilliseconds(500);

PdClient NewClient() => new(duid, Iaid, 60, () => 0.5);

// RAND is pinned to 0.5, and every scattering call multiplies by 1 + (RAND * 0.2 - 0.1), so the factor is
// exactly 1.0. The delays asserted below are therefore the tables' numbers, not samples of a jitter.

byte[] AddressOf(string text) => IPAddress.Parse(text).GetAddressBytes();

byte[] Option(ushort code, byte[] data)
{
    var buffer = new byte[4 + data.Length];
    BinaryPrimitives.WriteUInt16BigEndian(buffer, code);
    BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(2), (ushort)data.Length);
    data.CopyTo(buffer, 4);
    return buffer;
}

byte[] UInt16(ushort value) => new[] { (byte)(value >> 8), (byte)value };

byte[] UInt32(uint value) => new[] { (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value };

byte[] Message(byte kind, uint xid, params byte[][] options)
{
    var body = new List<byte> { kind, (byte)(xid >> 16), (byte)(xid >> 8), (byte)xid };
    foreach (var option in options) body.AddRange(option);
    return body.ToArray();
}

byte[] IaPdBody(uint iaid, uint t1, uint t2, params byte[][] inner)
{
    var body = new List<byte>();
    body.AddRange(UInt32(iaid));
    body.AddRange(UInt32(t1));
    body.AddRange(UInt32(t2));
    foreach (var option in inner) body.AddRange(option);
    return body.ToArray();
}

byte[] IaPrefixBody(uint preferred, uint valid, byte length, string prefix)
{
    var body = new List<byte>();
    body.AddRange(UInt32(preferred));
    body.AddRange(UInt32(valid));
    body.Add(length);
    body.AddRange(AddressOf(prefix));
    return body.ToArray();
}

(uint Iaid, uint T1, uint T2, List<(ushort Code, byte[] Data)> Inner) IaPdOf(byte[] data)
{
    var inner = new List<(ushort, byte[])>();
    for (var i = 12; i + 4 <= data.Length;)
    {
        var code = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(i));
        var length = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(i + 2));
        if (i + 4 + length > data.Length) break;
        inner.Add((code, data.AsSpan(i + 4, length).ToArray()));
        i += 4 + length;
    }
    return (BinaryPrimitives.ReadUInt32BigEndian(data),
        BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(4)),
        BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(8)), inner);
}

(uint Preferred, uint Valid, byte Length, byte[] Address) PrefixOf(byte[] data) =>
    (BinaryPrimitives.ReadUInt32BigEndian(data),
        BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(4)),
        data[8],
        data.AsSpan(9, 16).ToArray());

uint XidOf(byte[] datagram) => (uint)(datagram[1] << 16 | datagram[2] << 8 | datagram[3]);

bool HasCode(byte[] oro, ushort code)
{
    for (var i = 0; i + 2 <= oro.Length; i += 2)
        if (BinaryPrimitives.ReadUInt16BigEndian(oro.AsSpan(i)) == code) return true;
    return false;
}

PdTransmit TransmitOf(IReadOnlyList<PdStep> steps, string what)
{
    var sends = steps.OfType<PdTransmit>().ToList();
    Expect(sends.Count == 1, $"{what}: exactly one transmission, got {sends.Count}");
    return sends.Count == 1 ? sends[0] : new PdTransmit(new byte[4], "missing");
}

// Solicit, Advertise, Request and Reply in one call, answered at the same instant every exchange below
// starts from, so the T1/T2 arithmetic in each case reads off a single base time.
PdClient Bind(DateTime at, uint t1, uint t2, uint preferred, uint valid, string prefix)
{
    var client = NewClient();
    client.Start(at);
    var solicit = TransmitOf(client.Poll(at + half), "Bind: Solicit");
    var advertise = Message(2, XidOf(solicit.Datagram), Option(1, duid), Option(2, serverDuid),
        Option(25, IaPdBody(Iaid, t1, t2, Option(26, IaPrefixBody(preferred, valid, 61, prefix)))));
    var request = TransmitOf(client.Receive(advertise, serverA, at + half), "Bind: Request");
    var reply = Message(7, XidOf(request.Datagram), Option(1, duid), Option(2, serverDuid),
        Option(25, IaPdBody(Iaid, t1, t2, Option(26, IaPrefixBody(preferred, valid, 61, prefix)))));
    client.Receive(reply, serverA, at + half);
    return client;
}

// A client that has solicited and is waiting for its Reply, plus the transaction ID that Reply must carry.
// 'advertiseExtra' is a top-level option to ride on the Advertise, which is where a server sends SOL_MAX_RT.
(PdClient Client, uint RequestXid) Requesting(byte[]? advertiseExtra = null)
{
    var client = NewClient();
    client.Start(t0);
    var solicit = TransmitOf(client.Poll(t0 + half), "Requesting: Solicit");
    var advertiseOptions = new List<byte[]>
    {
        Option(1, duid),
        Option(2, serverDuid),
        Option(25, IaPdBody(Iaid, 0, 0, Option(26, IaPrefixBody(0, 0, 60, "::")))),
    };
    if (advertiseExtra is not null) advertiseOptions.Add(advertiseExtra);
    var advertise = Message(2, XidOf(solicit.Datagram), advertiseOptions.ToArray());
    var request = TransmitOf(client.Receive(advertise, serverA, t0 + half), "Requesting: Request");
    return (client, XidOf(request.Datagram));
}

// --- the identity this client presents ------------------------------------------------------------
Expect(duid.SequenceEqual(new byte[] { 0x00, 0x03, 0x00, 0x01, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 }),
    "the client identifier is DUID-LL: type 3, hardware type 1, then the MAC (RFC 8415 §11.4)");

// --- what a Solicit carries ------------------------------------------------------------------------
var sol = NewClient();
Expect(sol.Start(t0).Count == 0, "Start arms the first Solicit and sends nothing");
Expect(sol.State == PdState.Soliciting, "and the client is Soliciting");
Expect(sol.Poll(t0).Count == 0, "the first Solicit waits out a delay below SOL_MAX_DELAY (RFC 8415 §18.2.1)");
var solicitSend = TransmitOf(sol.Poll(t0 + half), "the first Solicit");
var solicit = new Parsed(solicitSend.Datagram);
Expect(solicit.Kind == 1, $"the message type is Solicit, got {solicit.Kind}");
Expect(solicit.Xid is > 0 and <= 0xFFFFFF, $"the transaction ID is three octets, got {solicit.Xid}");
Expect(solicit.Find(1)?.SequenceEqual(duid) == true, "it carries this client's DUID");
Expect(solicit.Find(2) is null, "a Solicit names no server");
Expect(solicit.Find(8) is { Length: 2 } elapsed0 && elapsed0[0] == 0 && elapsed0[1] == 0,
    "Elapsed Time is zero on the first transmission (RFC 8415 §21.9)");
Expect(solicit.Find(25) is not null, "the Solicit carries an IA_PD");
if (solicit.Find(25) is { } iaPd)
{
    var (iaid, iaT1, iaT2, inner) = IaPdOf(iaPd);
    Expect(iaid == Iaid, $"the IA_PD is the client's own IAID, got {iaid:x8}");
    Expect(iaT1 == 0 && iaT2 == 0, "a client's IA_PD sets T1 and T2 to 0 (RFC 8415 §21.21)");
    var hint = inner.FirstOrDefault(option => option.Code == 26);
    Expect(hint.Data is { Length: 25 }, "the IA_PD carries an IA Prefix hint");
    if (hint.Data is { Length: 25 } hintData)
    {
        var (_, _, hintLength, hintAddress) = PrefixOf(hintData);
        Expect(hintLength == 60, $"the hint asks for a /60, got /{hintLength}");
        Expect(hintAddress.All(value => value == 0),
            "the hint's prefix is zero, which is only legal as a length hint (RFC 8415 §18.2.4)");
    }
}
Expect(solicit.Find(6) is { } oro && HasCode(oro, 82) && HasCode(oro, 23),
    "the ORO asks for SOL_MAX_RT and the DNS servers (RFC 8415 §21.24)");

var retransmitted = new Parsed(TransmitOf(sol.Poll(t0 + half + TimeSpan.FromSeconds(1)), "the second Solicit").Datagram);
Expect(retransmitted.Kind == 1 && retransmitted.Xid == solicit.Xid,
    "a retransmission repeats the transaction ID (RFC 8415 §16.1)");
Expect(retransmitted.Find(8) is { Length: 2 } elapsed1 && BinaryPrimitives.ReadUInt16BigEndian(elapsed1) == 100,
    "Elapsed Time counts hundredths of a second since the first transmission (RFC 8415 §21.9)");

Expect(sol.Receive(new byte[] { 99, 0, 0, 1 }, serverA, t0 + half).Count == 0,
    "a message type the client does not know is discarded (RFC 8415 §16)");
Expect(sol.Receive(new byte[] { 1, 0 }, serverA, t0 + half).Count == 0,
    "a datagram too short for the four-octet header is discarded");
Expect(sol.Receive(new byte[] { 1, 0, 0, 1, 0, 1, 0, 9 }, serverA, t0 + half).Count == 0,
    "an option that claims more octets than the datagram holds is discarded");
Expect(sol.State == PdState.Soliciting, "and none of those malformed inputs moved the client");

// --- Advertise to Request --------------------------------------------------------------------------
var exchange = NewClient();
exchange.Start(t0);
var firstSolicit = TransmitOf(exchange.Poll(t0 + half), "Solicit");
var solicitXid = XidOf(firstSolicit.Datagram);

var noServerId = Message(2, solicitXid, Option(1, duid), Option(25, IaPdBody(Iaid, 0, 0)));
Expect(exchange.Receive(noServerId, serverA, t0 + half).Count == 0,
    "an Advertise without a Server Identifier is discarded (RFC 8415 §16.3)");
var foreignClient = Message(2, solicitXid, Option(1, otherServerDuid), Option(2, serverDuid),
    Option(25, IaPdBody(Iaid, 0, 0)));
Expect(exchange.Receive(foreignClient, serverA, t0 + half).Count == 0,
    "an Advertise naming another DUID is discarded (RFC 8415 §16.3)");
Expect(exchange.State == PdState.Soliciting, "and the client is still Soliciting");

var advertised = Message(2, solicitXid, Option(1, duid), Option(2, serverDuid),
    Option(25, IaPdBody(Iaid, 21600, 34560, Option(26, IaPrefixBody(43200, 86400, 61, F18)))));
var requestSend = TransmitOf(exchange.Receive(advertised, serverA, t0 + half), "the Request after an Advertise");
var request = new Parsed(requestSend.Datagram);
Expect(request.Kind == 3, $"the message type is Request, got {request.Kind}");
Expect(request.Find(2)?.SequenceEqual(serverDuid) == true,
    "the Request names that server in a Server Identifier option (RFC 8415 §18.2.2)");
Expect(request.Xid != solicitXid, "the Request opens a transaction of its own (RFC 8415 §18.2.2)");
var requestIa = IaPdOf(request.Find(25)!);
Expect(requestIa.Iaid == Iaid, "and asks for the same IA_PD");
var echoed = PrefixOf(requestIa.Inner.First(option => option.Code == 26).Data);
Expect(echoed.Length == 61 && echoed.Address.SequenceEqual(AddressOf(F18)),
    "the Request repeats the offered prefix (RFC 8415 §18.2.2)");
Expect(exchange.State == PdState.Requesting, "the client is now Requesting");

// --- Reply validation and the delegation it installs ------------------------------------------------
var requestXid = XidOf(requestSend.Datagram);
var strayReply = Message(7, requestXid ^ 1, Option(1, duid), Option(2, serverDuid),
    Option(25, IaPdBody(Iaid, 21600, 34560, Option(26, IaPrefixBody(43200, 86400, 61, F18)))));
Expect(exchange.Receive(strayReply, serverA, t0 + half).Count == 0,
    "a Reply for another transaction is discarded (RFC 8415 §16.10)");
var unnamedReply = Message(7, requestXid, Option(1, duid),
    Option(25, IaPdBody(Iaid, 21600, 34560, Option(26, IaPrefixBody(43200, 86400, 61, F18)))));
Expect(exchange.Receive(unnamedReply, serverA, t0 + half).Count == 0,
    "a Reply without a Server Identifier is discarded (RFC 8415 §16.10)");
Expect(exchange.Prefix is null, "so nothing has been installed yet");

var replyAt = t0 + half;
var grantedReply = Message(7, requestXid, Option(1, duid), Option(2, serverDuid),
    Option(25, IaPdBody(Iaid, 21600, 34560, Option(26, IaPrefixBody(43200, 86400, 61, F18)))));
var installSteps = exchange.Receive(grantedReply, serverA, replyAt);
Expect(installSteps.OfType<PdTransmit>().Count() == 0, "a Reply needs no answer");
var delegated = installSteps.OfType<PdDelegated>().SingleOrDefault();
Expect(delegated is not null, "the Reply installs a delegation");
if (delegated is not null)
{
    Expect(delegated.Prefix.ToString() == $"{F18}/61", $"the delegated prefix is the one granted, got {delegated.Prefix}");
    Expect(delegated.Preferred == TimeSpan.FromHours(12), $"the preferred lifetime is 12 h, got {delegated.Preferred}");
    Expect(delegated.Valid == TimeSpan.FromHours(24), $"the valid lifetime is 24 h, got {delegated.Valid}");
    Expect(delegated.Server == serverA.ToString(), $"the delegation names the server it came from, got {delegated.Server}");
}
Expect(exchange.State == PdState.Bound, "and the client is Bound");

// The resolver the Reply names travels with the delegation, because the advertisement that hands out the
// prefix is the only place a host configuring itself by SLAAC can learn it (RFC 8106 §5.1).
var (resolved, resolvedXid) = Requesting();
var maybeResolver = AddressOf("2001:db8:1:f10::1");
var resolverReply = Message(7, resolvedXid, Option(1, duid), Option(2, serverDuid),
    Option(23, maybeResolver),
    Option(25, IaPdBody(Iaid, 21600, 34560, Option(26, IaPrefixBody(43200, 86400, 61, F18)))));
var resolvedDelegated = resolved.Receive(resolverReply, serverA, t0 + TimeSpan.FromSeconds(1))
    .OfType<PdDelegated>().SingleOrDefault();
Expect(resolvedDelegated?.Dns.Count == 1 && resolvedDelegated.Dns[0].SequenceEqual(maybeResolver),
    "the Reply's resolver list is carried with the delegation (RFC 3646 §3)");

var (unresolved, unresolvedXid) = Requesting();
var unresolvedReply = Message(7, unresolvedXid, Option(1, duid), Option(2, serverDuid),
    Option(25, IaPdBody(Iaid, 21600, 34560, Option(26, IaPrefixBody(43200, 86400, 61, F18)))));
Expect(unresolved.Receive(unresolvedReply, serverA, t0 + TimeSpan.FromSeconds(1))
       .OfType<PdDelegated>().SingleOrDefault()?.Dns.Count == 0,
    "an answer that names none leaves the list empty rather than null");

var (tailed, tailedXid) = Requesting();
var tailedDns = new List<byte>(maybeResolver) { 1, 2, 3, 4 };
var tailedReply = Message(7, tailedXid, Option(1, duid), Option(2, serverDuid),
    Option(23, tailedDns.ToArray()),
    Option(25, IaPdBody(Iaid, 21600, 34560, Option(26, IaPrefixBody(43200, 86400, 61, F18)))));
var tailedDelegated = tailed.Receive(tailedReply, serverA, t0 + TimeSpan.FromSeconds(1))
    .OfType<PdDelegated>().SingleOrDefault();
Expect(tailedDelegated?.Dns.Count == 1 && tailedDelegated.Dns[0].Length == 16,
    "a tail that is not a whole address names no server (RFC 3646 §3)");

// --- Renew at T1, retransmit before T2 ---------------------------------------------------------------
var t1At = replyAt + TimeSpan.FromSeconds(21600);
Expect(exchange.Poll(t1At - TimeSpan.FromSeconds(1)).Count == 0, "nothing is sent before T1");
var renewSend = TransmitOf(exchange.Poll(t1At), "Renew at T1");
var renew = new Parsed(renewSend.Datagram);
Expect(renew.Kind == 5, $"the message type at T1 is Renew, got {renew.Kind}");
Expect(renew.Find(2)?.SequenceEqual(serverDuid) == true, "and names it (RFC 8415 §18.2.4)");
Expect(renew.Xid != requestXid, "the Renew opens its own transaction");
var renewed = PrefixOf(IaPdOf(renew.Find(25)!).Inner.First(option => option.Code == 26).Data);
Expect(renewed.Length == 61 && renewed.Address.SequenceEqual(AddressOf(F18)),
    "the Renew names the prefix it wants extended (RFC 8415 §18.2.4)");
Expect(exchange.State == PdState.Renewing, "the client is Renewing");

var renewAgain = new Parsed(TransmitOf(exchange.Poll(t1At + TimeSpan.FromSeconds(10)), "the Renew retransmission").Datagram);
Expect(renewAgain.Kind == 5 && renewAgain.Xid == renew.Xid, "a Renew retransmits its transaction ID");
Expect(renewAgain.Find(8) is { Length: 2 } elapsed2 && BinaryPrimitives.ReadUInt16BigEndian(elapsed2) == 1000,
    "its Elapsed Time reaches 10.00 s (RFC 8415 §21.9)");

// --- Rebind at T2, and a Reply from a server the client never named ---------------------------------
var t2At = replyAt + TimeSpan.FromSeconds(34560);
var rebindSend = TransmitOf(exchange.Poll(t2At), "Rebind at T2");
var rebind = new Parsed(rebindSend.Datagram);
Expect(rebind.Kind == 6, $"the message type at T2 is Rebind, got {rebind.Kind}");
Expect(rebind.Find(2) is null, "a Rebind carries no Server Identifier (RFC 8415 §18.2.5)");
Expect(rebind.Xid != renew.Xid, "the Rebind opens its own transaction");
Expect(exchange.State == PdState.Rebinding, "the client is Rebinding");

var rebindReply = Message(7, rebind.Xid, Option(1, duid), Option(2, otherServerDuid),
    Option(25, IaPdBody(Iaid, 21600, 34560, Option(26, IaPrefixBody(43200, 86400, 61, F18)))));
var rebindSteps = exchange.Receive(rebindReply, serverB, t2At);
Expect(rebindSteps.OfType<PdDelegated>().Count() == 1 && exchange.State == PdState.Bound,
    "the Rebind's Reply is accepted from a server and DUID the client never named (RFC 8415 §16.10)");
// "the server with which the client most recently communicated" (RFC 8415 §18.2.4) is the one that
// answered the Rebind, not the one whose Advertise started the exchange.
var afterRebind = new Parsed(TransmitOf(exchange.Poll(t2At + TimeSpan.FromSeconds(21600)),
    "the Renew after a Rebind").Datagram);
Expect(afterRebind.Kind == 5 && afterRebind.Find(2)?.SequenceEqual(otherServerDuid) == true,
    "the next Renew names the server whose Reply bound the client, not the first one");

// --- host bits are masked, and a moving prefix is withdrawn before it is replaced --------------------
var moving = Bind(t0, 21600, 34560, 43200, 86400, F18);
var movingRenewAt = t0 + half + TimeSpan.FromSeconds(21600);
var movingRenewSend = TransmitOf(moving.Poll(movingRenewAt), "the Renew of a moving delegation");
var maskedReply = Message(7, XidOf(movingRenewSend.Datagram), Option(1, duid), Option(2, serverDuid),
    Option(25, IaPdBody(Iaid, 21600, 34560, Option(26, IaPrefixBody(43200, 86400, 61, "2001:db8:1:f1b::")))));
var maskedSteps = moving.Receive(maskedReply, serverA, movingRenewAt);
Expect(maskedSteps.OfType<PdWithdrawn>().Count() == 0,
    "a prefix that differs only past its length is the same prefix, so nothing is withdrawn");
Expect(maskedSteps.OfType<PdDelegated>().SingleOrDefault()?.Prefix.ToString() == $"{F18}/61",
    "and the host bits past /61 are masked off the installed prefix");

var changeAt = movingRenewAt + TimeSpan.FromSeconds(21600);
var changeSend = TransmitOf(moving.Poll(changeAt), "the next Renew");
var movedReply = Message(7, XidOf(changeSend.Datagram), Option(1, duid), Option(2, serverDuid),
    Option(25, IaPdBody(Iaid, 21600, 34560, Option(26, IaPrefixBody(43200, 86400, 61, F20)))));
var changeSteps = moving.Receive(movedReply, serverA, changeAt);
Expect(changeSteps.Count == 2 && changeSteps[0] is PdWithdrawn && changeSteps[1] is PdDelegated,
    "a delegation that moves is withdrawn in the same step that installs the replacement");
if (changeSteps.Count == 2 && changeSteps[0] is PdWithdrawn gone && changeSteps[1] is PdDelegated arriving)
{
    Expect(gone.Prefix?.ToString() == $"{F18}/61", $"the withdrawal names the prefix being abandoned, got {gone.Prefix}");
    Expect(arriving.Prefix.ToString() == $"{F20}/61", $"the delegation names the new prefix, got {arriving.Prefix}");
}

// --- Release: the prefix goes first, then the datagram ------------------------------------------------
var releaseSteps = moving.Release(changeAt);
Expect(releaseSteps.Count == 2 && releaseSteps[0] is PdWithdrawn && releaseSteps[1] is PdTransmit,
    "a Release advertises the prefix with zero lifetimes before it sends anything (RFC 8415 §18.2.7)");
var releaseSend = releaseSteps.OfType<PdTransmit>().SingleOrDefault() ?? new PdTransmit(new byte[4], "missing");
var release = new Parsed(releaseSend.Datagram);
Expect(release.Kind == 8, $"the message type is Release, got {release.Kind}");
Expect(release.Find(2)?.SequenceEqual(serverDuid) == true, "and names the server that granted the prefix");
var released = PrefixOf(IaPdOf(release.Find(25)!).Inner.First(option => option.Code == 26).Data);
Expect(released.Length == 61 && released.Address.SequenceEqual(AddressOf(F20)),
    "the released lease is the prefix named in the IA (RFC 8415 §18.2.7)");
Expect(moving.State == PdState.Released, "the client is Released");
Expect(moving.Release(changeAt).Count == 0, "releasing again releases nothing");
Expect(moving.Receive(movedReply, serverA, changeAt).Count == 0 && moving.State == PdState.Released,
    "and a Reply that arrives after the release does not revive it");
Expect(NewClient().Release(t0).Count == 0, "a client with no binding releases nothing");

// --- T1 and T2 left to the client ------------------------------------------------------------------
var defaults = Bind(t0, 0, 0, 3600, 7200, F18);
Expect(defaults.Poll(t0 + half + TimeSpan.FromSeconds(1799)).Count == 0,
    "with T1 absent, nothing is sent before half the preferred lifetime");
Expect(defaults.Poll(t0 + half + TimeSpan.FromSeconds(1800)).OfType<PdTransmit>().SingleOrDefault()?.Datagram[0] == 5,
    "T1 defaults to half the preferred lifetime (RFC 8415 §14.2)");
Expect(defaults.Poll(t0 + half + TimeSpan.FromSeconds(2880)).OfType<PdTransmit>().SingleOrDefault()?.Datagram[0] == 6,
    "T2 defaults to four fifths of the preferred lifetime (RFC 8415 §14.2)");

var t2Only = Bind(t0, 0, 500, 3600, 7200, F18);
Expect(t2Only.Poll(t0 + half + TimeSpan.FromSeconds(499)).Count == 0, "a server-chosen T2 still holds when T1 is absent");
Expect(t2Only.Poll(t0 + half + TimeSpan.FromSeconds(500)).OfType<PdTransmit>().SingleOrDefault()?.Datagram[0] == 6,
    "a client-chosen T1 cannot postpone a server-chosen T2");

var inverted = Requesting();
var invertedReply = Message(7, inverted.RequestXid, Option(1, duid), Option(2, serverDuid),
    Option(25, IaPdBody(Iaid, 3600, 1800, Option(26, IaPrefixBody(43200, 86400, 61, F18)))));
var invertedSteps = inverted.Client.Receive(invertedReply, serverA, t0 + half);
Expect(invertedSteps.Count == 1 && invertedSteps[0] is PdWithdrawn { Prefix: null } && inverted.Client.State == PdState.Failed,
    "an IA_PD whose T1 is later than its T2 is discarded, so the client is left with nothing (RFC 8415 §21.21)");

// --- refusals --------------------------------------------------------------------------------------
var refused = Requesting();
var noPrefixReply = Message(7, refused.RequestXid, Option(1, duid), Option(2, serverDuid),
    Option(25, IaPdBody(Iaid, 0, 0, Option(13, UInt16(6)))));
var noPrefixSteps = refused.Client.Receive(noPrefixReply, serverA, t0 + half);
Expect(noPrefixSteps.Count == 1 && noPrefixSteps[0] is PdWithdrawn { Prefix: null } && refused.Client.State == PdState.Failed,
    "NoPrefixAvail withdraws the (empty) delegation and fails the exchange (RFC 8415 §21.13)");

var tooLong = Requesting();
var longReply = Message(7, tooLong.RequestXid, Option(1, duid), Option(2, serverDuid),
    Option(25, IaPdBody(Iaid, 21600, 34560, Option(26, IaPrefixBody(43200, 86400, 80, "2001:db8:1:f18:1234::")))));
var longSteps = tooLong.Client.Receive(longReply, serverA, t0 + half);
Expect(longSteps.Count == 1 && longSteps[0] is PdWithdrawn { Prefix: null } && tooLong.Client.State == PdState.Failed,
    "a delegation longer than /64 cannot seed a LAN and is refused");

// --- the valid lifetime runs out, and the retry waits 60 s ------------------------------------------
var expiring = Bind(t0, 21600, 34560, 3600, 7200, F18);
var expiryAt = t0 + half + TimeSpan.FromSeconds(7200);
var expirySteps = expiring.Poll(expiryAt);
Expect(expirySteps.Count == 1 && expirySteps[0] is PdWithdrawn { Prefix: not null } expired &&
       expired.Prefix.ToString() == $"{F18}/61",
    "the prefix is withdrawn when its valid lifetime runs out");
Expect(expiring.Prefix is null && expiring.State == PdState.Failed, "and the client holds nothing");
Expect(expiring.Poll(expiryAt + TimeSpan.FromSeconds(59)).Count == 0, "it does not retry before 60 s");
Expect(expiring.Poll(expiryAt + TimeSpan.FromSeconds(60)).Count == 0 && expiring.State == PdState.Soliciting,
    "at 60 s it starts a fresh Solicit");
Expect(expiring.Poll(expiryAt + TimeSpan.FromSeconds(60) + half).OfType<PdTransmit>().SingleOrDefault()?.Datagram[0] == 1,
    "and that Solicit leaves once its own delay is over");

// --- SOL_MAX_RT from the Advertise caps the Solicit backoff ----------------------------------------
// A refusal is how the client is made to keep soliciting: the cap survives into the retry, and the
// backoff is then 1, 2, 4, 8, 16, 32 s and then the cap. The control client sees the same sequence
// without the option, so the extra send below is the option's doing and not the schedule's.
(PdClient Client, DateTime Restart) FailedExchange(bool withCap)
{
    var (client, requestXid) = Requesting(withCap ? Option(82, UInt32(60)) : null);
    var refusal = Message(7, requestXid, Option(1, duid), Option(2, serverDuid),
        Option(25, IaPdBody(Iaid, 0, 0, Option(13, UInt16(6)))));
    client.Receive(refusal, serverA, t0 + half);
    return (client, t0 + half + TimeSpan.FromSeconds(60));
}

DateTime RunBackoff(PdClient client, DateTime restart)
{
    client.Poll(restart);
    var at = restart + half;
    Expect(client.Poll(at).OfType<PdTransmit>().Count() == 1, "the retry Solicits once its delay is over");
    foreach (var gap in new[] { 1, 2, 4, 8, 16, 32 })
    {
        at += TimeSpan.FromSeconds(gap);
        Expect(client.Poll(at).OfType<PdTransmit>().Count() == 1, $"the retry Solicits again after {gap} s");
    }
    return at;
}

var (capped, cappedRestart) = FailedExchange(true);
RunBackoff(capped, cappedRestart);
Expect(capped.Poll(cappedRestart + TimeSpan.FromSeconds(125)).OfType<PdTransmit>().Count() == 1,
    "SOL_MAX_RT from the Advertise caps that backoff at 60 s (RFC 8415 §21.24)");

var (plain, plainRestart) = FailedExchange(false);
RunBackoff(plain, plainRestart);
Expect(plain.Poll(plainRestart + TimeSpan.FromSeconds(125)).OfType<PdTransmit>().Count() == 0,
    "without the option the same schedule still waits 64 s, so the send above is the option's doing");

// --- what a delegated prefix can become ------------------------------------------------------------
var delegatedPrefix = new Dhcp6Prefix(61, AddressOf(F18));
Expect(delegatedPrefix.TryLanSubnet(out var lan) && lan.ToString() == $"{F18}/64",
    "a /61 delegation seeds the LAN from its first /64 (RFC 4862 §5.5)");
Expect(!new Dhcp6Prefix(72, AddressOf("2001:db8:1:f18:1200::")).TryLanSubnet(out _),
    "a /72 cannot be split into a /64 the LAN could address from");
Expect(new Dhcp6Prefix(61, AddressOf("2001:db8:1:f1b::")).Masked().ToString() == $"{F18}/61",
    "Masked clears the bits past the prefix length");

// RFC 4443 §2.3's checksum, written here on its own: the pseudo-header is prepended to the message and
// the 16-bit one's complement sum is folded until it fits. The product's output is judged against this,
// so a mistake in one does not hide in the other.
ushort IndependentChecksum(ReadOnlySpan<byte> message, IPAddress source, IPAddress destination)
{
    var bytes = new List<byte>();
    bytes.AddRange(source.GetAddressBytes());
    bytes.AddRange(destination.GetAddressBytes());
    var length = (uint)message.Length;
    bytes.AddRange(new byte[] { (byte)(length >> 24), (byte)(length >> 16), (byte)(length >> 8), (byte)length, 0, 0, 0, 58 });
    bytes.AddRange(message.ToArray());
    var sum = 0u;
    for (var i = 0; i < bytes.Count; i += 2)
    {
        var word = (uint)bytes[i] << 8;
        if (i + 1 < bytes.Count) word |= bytes[i + 1];
        sum += word;
    }
    while (sum > 0xFFFF) sum = (sum & 0xFFFF) + (sum >> 16);
    return (ushort)~sum;
}

// RFC 4861 §6.1.1's message, laid out here rather than through Ra6: type, code, checksum, reserved, then
// at most one Source Link-Layer Address option.
byte[] SolicitBytes(byte[]? linkLayer)
{
    var message = new List<byte> { 133, 0, 0, 0, 0, 0, 0, 0 };
    if (linkLayer is not null)
    {
        message.AddRange(new byte[] { 1, 1 });
        message.AddRange(linkLayer);
    }
    return message.ToArray();
}

// --- the advertisement that hands the LAN its prefix -------------------------------------------------
// The builder is given the lifetimes as they stand; the shell hands it what is left of them. The octets
// are read back option by option below, not through the builder, so a field written in the wrong place
// shows up here instead of agreeing with itself.
var lanLinkLocal = IPAddress.Parse("fe80::a8bb:ccff:fe12:3456");
var allNodes = IPAddress.Parse("ff02::1");
var lanMac = new byte[] { 0xaa, 0xbb, 0xcc, 0x12, 0x34, 0x56 };
var rdnsAddress = AddressOf("2001:db8:1:f10::1");
var ra = new RaAdvertisement
{
    LinkLayerAddress = lanMac,
    Prefix = new Dhcp6Prefix(64, AddressOf(F18)),
    PreferredLifetime = 43200,
    ValidLifetime = 86400,
    Mtu = 1492,
    RouterLifetime = 1800,
    RecursiveDns = new[] { rdnsAddress },
    DnsLifetime = 1800,
};
var advertisement = Ra6.Build(ra, lanLinkLocal, allNodes);

Expect(advertisement.Length == 88, $"SLLA, MTU, PIO and RDNSS come to 88 octets, got {advertisement.Length}");
Expect(advertisement[0] == 134 && advertisement[1] == 0, "the message is a Router Advertisement with code zero");
Expect(advertisement[4] == 64 && advertisement[5] == 0,
    "it suggests hop limit 64 and clears the managed and other-config flags, so a host configures from it");
Expect(BinaryPrimitives.ReadUInt16BigEndian(advertisement.AsSpan(6)) == 1800,
    "the router stays a default router for 1800 seconds (RFC 4861 §6.2.1)");
Expect(!advertisement.AsSpan(8, 8).ContainsAnyExcept((byte)0),
    "reachable time and retransmission timer are left to the host");

Expect(advertisement[16] == 1 && advertisement[17] == 1 && advertisement.AsSpan(18, 6).SequenceEqual(lanMac),
    "the Source Link-Layer Address option carries the LAN adapter's address (RFC 4861 §4.6.1)");
Expect(advertisement[24] == 5 && advertisement[25] == 1
       && BinaryPrimitives.ReadUInt32BigEndian(advertisement.AsSpan(28)) == 1492,
    "the MTU option carries the WAN's 1492 octets (RFC 4861 §4.6.4)");

// §4.6.4 makes the MTU option optional, and the shell passes zero when the WAN's MTU cannot be read:
// claiming an MTU of zero would be worse than naming none.
var noMtu = Ra6.Build(ra with { Mtu = 0 }, lanLinkLocal, allNodes);
Expect(noMtu.Length == 80 && noMtu[24] == 3,
    "with no MTU known the option is left out and the prefix option follows the link-layer one");

var pio = 32;
Expect(advertisement[pio] == 3 && advertisement[pio + 1] == 4 && advertisement[pio + 2] == 64,
    "the Prefix Information option describes the /64 the LAN is addressed from");
Expect(advertisement[pio + 3] == 0xC0, "both the on-link and autonomous flags are set");
Expect(BinaryPrimitives.ReadUInt32BigEndian(advertisement.AsSpan(pio + 4)) == 86400
       && BinaryPrimitives.ReadUInt32BigEndian(advertisement.AsSpan(pio + 8)) == 43200,
    "the delegated valid and preferred lifetimes are repeated unchanged");
Expect(advertisement.AsSpan(pio + 16, 16).SequenceEqual(AddressOf(F18)),
    "and so is the prefix itself");

var rdns = 64;
Expect(advertisement[rdns] == 25 && advertisement[rdns + 1] == 3,
    "the RDNSS option's length counts 1 + 2 per address (RFC 8106 §5.1)");
Expect(BinaryPrimitives.ReadUInt32BigEndian(advertisement.AsSpan(rdns + 4)) == 1800,
    "the resolver is good for three MaxRtrAdvIntervals, as RFC 8106 §5.1 recommends");
Expect(advertisement.AsSpan(rdns + 8, 16).SequenceEqual(rdnsAddress),
    "and the address is the one the builder was handed");

// --- which address that option names ------------------------------------------------------------------
// The encoder above is faithful to whatever it is given; this is the choice. A run that answers DNS
// advertises its own LAN address, so a client's answer comes from the resolver that takes the ECH
// configuration out of it rather than from one this program never sees.
var ownResolver = IPAddress.Parse(F18 + "1");
var delegatedResolvers = new[] { AddressOf("2001:db8:1:f10::1"), AddressOf("2001:db8:1:f10::2") };
var chosen = V6Router.RecursiveDns(ownResolver, delegatedResolvers);
Expect(chosen.Length == 1 && chosen[0].SequenceEqual(AddressOf(F18 + "1")),
    "a run that answers advertises its own LAN address, and only that one");
Expect(V6Router.RecursiveDns(null, delegatedResolvers).Select(address => new IPAddress(address).ToString())
       .SequenceEqual(new[] { "2001:db8:1:f10::1", "2001:db8:1:f10::2" }),
    "a run that answers nothing advertises the delegation's resolver option unchanged");
Expect(V6Router.RecursiveDns(null, Array.Empty<byte[]>()).Length == 0,
    "and a delegation that named no resolver leaves the option out");
Expect(Ra6.Build(ra with { RecursiveDns = chosen }, lanLinkLocal, allNodes).AsSpan(rdns + 8, 16)
       .SequenceEqual(AddressOf(F18 + "1")),
    "the address it chose is the one the option on the wire carries");
var noResolver = Ra6.Build(ra with { RecursiveDns = Array.Empty<byte[]>() }, lanLinkLocal, allNodes);
Expect(noResolver.Length == advertisement.Length - 24,
    "with no resolver to name the option is left out rather than sent empty");

var raField = BinaryPrimitives.ReadUInt16BigEndian(advertisement.AsSpan(2));
var raCopy = (byte[])advertisement.Clone();
raCopy[2] = 0;
raCopy[3] = 0;
Expect(raField == IndependentChecksum(raCopy, lanLinkLocal, allNodes),
    "the checksum covers the IPv6 pseudo-header and the message (RFC 4443 §2.3)");
raCopy[pio + 16] ^= 0x01;
Expect(raField != IndependentChecksum(raCopy, lanLinkLocal, allNodes),
    "one changed octet produces a different checksum, so the assertion above is not vacuous");

var withdrawn = Ra6.Withdraw(ra, lanLinkLocal, allNodes);
Expect(BinaryPrimitives.ReadUInt16BigEndian(withdrawn.AsSpan(6)) == 0,
    "the revocation names no default router (RFC 4861 §6.2.5)");
Expect(BinaryPrimitives.ReadUInt32BigEndian(withdrawn.AsSpan(pio + 4)) == 0
       && BinaryPrimitives.ReadUInt32BigEndian(withdrawn.AsSpan(pio + 8)) == 0,
    "and advertises the prefix with both lifetimes zero (RFC 4862 §5.5.3(e))");
Expect(BinaryPrimitives.ReadUInt32BigEndian(withdrawn.AsSpan(rdns + 4)) == 0,
    "the resolver goes with it (RFC 8106 §5.1)");
var withdrawnCopy = (byte[])withdrawn.Clone();
withdrawnCopy[2] = 0;
withdrawnCopy[3] = 0;
Expect(BinaryPrimitives.ReadUInt16BigEndian(withdrawn.AsSpan(2))
       == IndependentChecksum(withdrawnCopy, lanLinkLocal, allNodes),
    "a revocation carries its own checksum");

// --- RFC 8781's PREF64 option -------------------------------------------------------------------------
// The prefix the DNS64 synthesized with, put on the link so a host that forms addresses for itself forms
// them the same way. Read back octet by octet, as above, because the two fields share one short and a
// shift that is one bit out still leaves a plausible-looking number.
// Walks the option list the way RFC 4861 §4.6 says to: type, then a length in 8-octet units.
static bool Carries(byte[] message, byte type)
{
    for (var offset = 16; offset + 2 <= message.Length;)
    {
        var length = message[offset + 1] * 8;
        if (length == 0 || offset + length > message.Length) return false;
        if (message[offset] == type) return true;
        offset += length;
    }
    return false;
}

var wellKnown = new Pref64Advertisement(Pref64Config.WellKnown, 1800);
var nsp = new Pref64Advertisement(Pref64Config.Parse("2001:db8:1:f18::/64")!, 1800);
var advertising = Ra6.Build(ra with { Pref64 = wellKnown }, lanLinkLocal, allNodes);
Expect(advertising.Length == 88 + 16, $"the option is one more 16-octet block, got {advertising.Length}");
Expect(Carries(advertising, Ra6.OptionPref64) && !Carries(advertisement, Ra6.OptionPref64),
    "an advertisement with no prefix to name carries no PREF64 option at all, and one with a prefix carries " +
    "it as a whole option - searched by walking the options, because 38 is also an octet of the prefix");

var pref64 = 88;
Expect(advertising[pref64] == 38 && advertising[pref64 + 1] == 2,
    "type 38, and §4's \"The sender MUST set the length to 2\" - two units of 8 octets");
Expect(BinaryPrimitives.ReadUInt16BigEndian(advertising.AsSpan(pref64 + 2)) == (225 << 3),
    $"the 13-bit Scaled Lifetime is 1800/8 and the /96 code is zero, got {BinaryPrimitives.ReadUInt16BigEndian(advertising.AsSpan(pref64 + 2))}");
Expect(advertising.AsSpan(pref64 + 4, 12).SequenceEqual(AddressOf("64:ff9b::")[..12]),
    "and the option's last twelve octets are \"bits 0 - 95 of the NAT64 prefix\"");
Expect(Ra6.PrefixLengthCode(96) == 0 && Ra6.PrefixLengthCode(64) == 1 && Ra6.PrefixLengthCode(56) == 2
       && Ra6.PrefixLengthCode(48) == 3 && Ra6.PrefixLengthCode(40) == 4 && Ra6.PrefixLengthCode(32) == 5,
    "§4's code table, read the way the option has to be written");

var nspWire = Ra6.Build(ra with { Pref64 = nsp }, lanLinkLocal, allNodes);
Expect(BinaryPrimitives.ReadUInt16BigEndian(nspWire.AsSpan(pref64 + 2)) == ((225 << 3) | 1),
    "a /64 takes code 1 in the three bits the lifetime does not reach");
Expect(nspWire.AsSpan(pref64 + 4, 12).SequenceEqual(AddressOf(F18)[..12]),
    "and its twelve prefix octets are the /64 followed by four zeros, which is what §4's figure asks for " +
    "when the prefix is shorter than 96 bits");

var advertisingCopy = (byte[])advertising.Clone();
advertisingCopy[2] = 0;
advertisingCopy[3] = 0;
Expect(BinaryPrimitives.ReadUInt16BigEndian(advertising.AsSpan(2))
       == IndependentChecksum(advertisingCopy, lanLinkLocal, allNodes),
    "the checksum is recomputed over the longer message, so the new option is inside what it covers");
advertisingCopy[pref64 + 4] ^= 0x01;
Expect(BinaryPrimitives.ReadUInt16BigEndian(advertising.AsSpan(2))
       != IndependentChecksum(advertisingCopy, lanLinkLocal, allNodes),
    "and one changed prefix octet changes it, so that assertion is not vacuous either");

// §4.1's two odd cases: zero is the withdrawal signal, and a nonzero lifetime under 8 seconds must not
// round away into it.
Expect(Ra6.ScaledLifetime(0) == 0, "a lifetime of zero is written as zero, which §4.1 reads as \"no longer use this\"");
Expect(Ra6.ScaledLifetime(1) == 1 && Ra6.ScaledLifetime(7) == 1,
    "a nonzero lifetime under 8 seconds becomes 1, not 0");
Expect(Ra6.ScaledLifetime(8) == 1 && Ra6.ScaledLifetime(9) == 2,
    "and the rounding is up to the next multiple of 8 before the divide, as §4.1 says");
Expect(Ra6.ScaledLifetime(65528) == Ra6.MaxScaledLifetime && Ra6.ScaledLifetime(100_000) == Ra6.MaxScaledLifetime,
    "the 13-bit field caps at 8191, which is §4.1's \"maximum lifetime of the NAT64 prefix is thus 65528 seconds\"");

var withdrawnPref64 = Ra6.Withdraw(ra with { Pref64 = nsp }, lanLinkLocal, allNodes);
Expect(withdrawnPref64.Length == 104 && withdrawnPref64[pref64] == 38
       && BinaryPrimitives.ReadUInt16BigEndian(withdrawnPref64.AsSpan(pref64 + 2)) == 1,
    "the revocation keeps the option and zeroes only its lifetime: dropping it would tell a host nothing, " +
    "and §4.1 names the zero lifetime as the way to take a prefix away");

Expect(Ra6.TrySolicitation(SolicitBytes(lanMac), out _),
    "a solicitation carrying a Source Link-Layer Address option is accepted");
Expect(Ra6.TrySolicitation(SolicitBytes(null), out _),
    "and one without an option is still a solicitation (RFC 4861 §6.1.1)");
Expect(!Ra6.TrySolicitation(advertisement, out var notSolicitation) && notSolicitation.Length > 0,
    "an advertisement is not a solicitation");
Expect(!Ra6.TrySolicitation(SolicitBytes(null).AsSpan(0, 7), out _), "a seven-octet message is not one");
var wrongCode = SolicitBytes(null);
wrongCode[1] = 1;
Expect(!Ra6.TrySolicitation(wrongCode, out _), "a non-zero code is not one (RFC 4861 §6.1.1)");
Expect(!Ra6.TrySolicitation(new byte[] { 133, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0xaa }, out _),
    "an option that runs past the end is rejected rather than read past");

var schedule = new RaSchedule(t0, () => 0.5);
Expect(schedule.MaxInterval == TimeSpan.FromSeconds(600) && schedule.MinInterval == TimeSpan.FromSeconds(198),
    "the default interval pair is 600 seconds and 0.33 of it (RFC 4861 §6.2.1)");
Expect(schedule.Due(t0), "the first advertisement is due as soon as the interface starts advertising");
schedule.Sent(t0);
Expect(schedule.NextDue == t0.AddSeconds(16), "the second is held to MAX_INITIAL_RTR_ADVERT_INTERVAL");
schedule.Sent(t0.AddSeconds(16));
Expect(schedule.NextDue == t0.AddSeconds(32), "so is the third");
schedule.Sent(t0.AddSeconds(32));
Expect(schedule.NextDue == t0.AddSeconds(32 + 399),
    "after MAX_INITIAL_RTR_ADVERTISEMENTS the interval is a uniform draw: 198 + 0.5 * (600 - 198)");

Expect(schedule.Solicit(t0.AddSeconds(40), multicast: true) == t0.AddSeconds(40.25),
    "a solicited multicast answer waits up to MAX_RA_DELAY_TIME (RFC 4861 §6.2.6)");
var queued = new RaSchedule(t0, () => 0.5);
queued.Sent(t0);
Expect(queued.Solicit(t0.AddSeconds(15.9), multicast: true) == t0.AddSeconds(16),
    "an answer that would land later than the scheduled advertisement gives way to it");

var rateLimited = new RaSchedule(t0, () => 0.5);
rateLimited.Sent(t0);
Expect(rateLimited.Solicit(t0.AddSeconds(1), multicast: true) == t0.AddSeconds(3.25),
    "a multicast answer within MIN_DELAY_BETWEEN_RAS waits three seconds after the last multicast one");
Expect(rateLimited.Solicit(t0.AddSeconds(1), multicast: false) == t0.AddSeconds(1.25),
    "a unicast answer is not a multicast advertisement, so neither limit applies to it");
rateLimited.Announce(t0.AddSeconds(60));
Expect(rateLimited.Due(t0.AddSeconds(60)) && rateLimited.NextDue == t0.AddSeconds(60),
    "a prefix change restarts the initial burst (RFC 4861 §6.2.4)");
rateLimited.Sent(t0.AddSeconds(60));
Expect(rateLimited.NextDue == t0.AddSeconds(76), "and the burst begins with the capped interval again");

// The trace is Router's only view of the IPv6 data plane: nothing on that path is rewritten, so whether a
// client's packet is being forwarded is read from these lines or not at all. Each packet is laid out here
// rather than through the product's builder, for the same reason as every other datagram in this file.
byte[] V6Packet(byte nextHeader, string source, string destination, params byte[] payload)
{
    var packet = new byte[40 + payload.Length];
    packet[0] = 0x60;
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4), (ushort)payload.Length);
    packet[6] = nextHeader;
    packet[7] = 64;
    AddressOf(source).CopyTo(packet, 8);
    AddressOf(destination).CopyTo(packet, 24);
    payload.CopyTo(packet, 40);
    return packet;
}

// Same job as AddressOf, but the text the description is compared against, so an octet offset that moved
// shows up as a different address rather than as the same one.
string V6(string text) => IPAddress.Parse(text).ToString();

var v6Source = "2001:db8:1:f18:1234:5678:9abc:def1";
var v6Dest = "2001:db8:2::1";
var tcpHeader = new byte[] { 0x30, 0x39, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0x20, 0x00, 0, 0, 0, 0 };
var tcp6 = V6Packet(6, v6Source, v6Dest, tcpHeader);
Expect(Host.Describe(tcp6) == $"tcp {V6(v6Source)}:12345 -> {V6(v6Dest)}:443",
    "an IPv6 TCP packet is described by its addresses and the ports at octet 40, which is the line a client's v6 flow shows up on");
var udp6 = V6Packet(17, v6Source, v6Dest, new byte[] { 0x30, 0x39, 0x00, 0x35, 0, 8, 0, 0 });
Expect(Host.Describe(udp6) == $"udp {V6(v6Source)}:12345 -> {V6(v6Dest)}:53",
    "and a UDP datagram likewise");

// RFC 8200 §4.1 lets a header sit in front of the transport, and the walk that finds it is the one the
// redirector swaps by and the reply leg rewrites by (TlsMitm/Ipv6Chain.cs). The trace has to report what
// those two act on: the first header stepped over, the transport it leads to, and that transport's own
// ports - not the option octets at 40.
byte[] Chain(params byte[][] parts)
{
    var all = new byte[parts.Sum(p => p.Length)];
    var at = 0;
    foreach (var part in parts) { part.CopyTo(all, at); at += part.Length; }
    return all;
}

Expect(Host.Describe(V6Packet(0, v6Source, v6Dest, Chain(new byte[] { 6, 0, 0, 0, 0, 0, 0, 0 }, tcpHeader)))
       == $"hopbyhop>tcp {V6(v6Source)}:12345 -> {V6(v6Dest)}:443",
    "a TCP segment behind §4.3's hop-by-hop header names the header and the transport, and reads its ports from behind it");
Expect(Host.Describe(V6Packet(0, v6Source, v6Dest,
       Chain(new byte[] { 60, 0, 0, 0, 0, 0, 0, 0 }, new byte[] { 6, 0, 0, 0, 0, 0, 0, 0 }, tcpHeader)))
       == $"hopbyhop>tcp {V6(v6Source)}:12345 -> {V6(v6Dest)}:443",
    "two headers in front of it are both walked, and the line names the first of them");
Expect(Host.Describe(V6Packet(0, v6Source, v6Dest, Chain(new byte[] { 44, 0, 0, 0, 0, 0, 0, 0 }, tcpHeader)))
       == $"hopbyhop {V6(v6Source)} -> {V6(v6Dest)}",
    "a chain that stops at §4.5's fragment header names the header it got to and invents no transport behind it");

var neighbourTarget = "2001:db8:1:f18::2";
var solicitation = new byte[24];
solicitation[0] = 135;
AddressOf(neighbourTarget).CopyTo(solicitation, 8);
var ns = V6Packet(58, "fe80::a8bb:ccff:fe12:3456", "ff02::1:ff00:2", solicitation);
Expect(Host.Describe(ns).Contains($"type=135 target={V6(neighbourTarget)}"),
    "a Neighbour Solicitation names the address being resolved (RFC 4861 §4.3), which is how a LAN host reaching this router is seen");
var tooBig = new byte[8];
tooBig[0] = 2;
BinaryPrimitives.WriteUInt32BigEndian(tooBig.AsSpan(4), 1492);
Expect(Host.Describe(V6Packet(58, v6Dest, v6Source, tooBig)).Contains("type=2 mtu=1492"),
    "a Packet Too Big carries the MTU that has to reach the client (RFC 4443 §3.2)");
Expect(Host.Describe(V6Packet(44, v6Source, v6Dest, new byte[8])) == $"fragment {V6(v6Source)} -> {V6(v6Dest)}",
    "an extension header is named rather than read as if it were a transport header");
Expect(Host.Describe(new byte[] { 0x60, 0, 0, 0 }) == "truncated-ipv6",
    "a packet cut off inside the fixed header says so instead of reading past it");
Expect(Host.Describe(V6Packet(6, v6Source, v6Dest)) == $"tcp {V6(v6Source)} -> {V6(v6Dest)}",
    "and one cut off before its ports is named without inventing a port pair");
Expect(Host.Describe(new byte[]
    {
        0x45, 0, 0, 24, 0, 0, 0, 0, 64, 6, 0, 0, 192, 0, 2, 1, 198, 51, 100, 1, 0x30, 0x39, 0x01, 0xbb,
    }) == "tcp 192.0.2.1:12345 -> 198.51.100.1:443",
    "an IPv4 packet still reads exactly as before, so the v6 branch did not take it over");

// --- Pref64: the IPv4-embedded address arithmetic, against RFC 6052's own layout ---------------------
// The six lengths of §2.1 and the figure of §2.2: the four octets begin where the prefix ends, and where
// that run would cross bits 64-71 it resumes behind them, so every embedding shorter than /96 carries a
// zero octet 8. The expected strings below are laid out by hand from the figure, not from the product.
var v4 = IPAddress.Parse("192.0.2.33");
Expect(Pref64.TryParse("64:ff9b::/96", out var wkp, out var wkl) && wkl == 96
       && wkp is not null && wkp.Equals(IPAddress.Parse("64:ff9b::")),
    "the well-known prefix parses at /96");
foreach (var (prefixText, len) in new[] { ("2001:db8::", 32), ("2001:db8:100::", 40),
    ("2001:db8:100::", 48), ("2001:db8:100::", 56), ("2001:db8:100::", 64) })
    Expect(Pref64.TryParse($"{prefixText}/{len}", out _, out var parsedLen) && parsedLen == len,
        $"and /{len} is one of the six lengths §2.1 allows");
Expect(!Pref64.TryParse("64:ff9b::/65", out _, out _), "a length outside the six is refused");
Expect(!Pref64.TryParse("64:ff9b::1/96", out _, out _),
    "a prefix whose host bits are set is refused: it names an address, not a prefix");
Expect(!Pref64.TryParse("192.0.2.0/24", out _, out _), "and an IPv4 prefix is refused outright");
Expect(Pref64.Embed(IPAddress.Parse("64:ff9b::"), 96, v4).Equals(IPAddress.Parse("64:ff9b::c000:221")),
    "the /96 embedding is §2.1's own example, 192.0.2.33 in the last four octets");
Expect(Pref64.Embed(IPAddress.Parse("2001:db8::"), 32, v4).Equals(IPAddress.Parse("2001:db8:c000:221::")),
    "at /32 the four octets sit directly behind the prefix and the rest is zero");
Expect(Pref64.Embed(IPAddress.Parse("2001:db8:100::"), 40, v4).Equals(IPAddress.Parse("2001:db8:1c0:2:21::")),
    "at /40 the run crosses octet 8, so its last octet resumes behind it");
Expect(Pref64.Embed(IPAddress.Parse("2001:db8:100::"), 48, v4).Equals(IPAddress.Parse("2001:db8:100:c000:2:2100::")),
    "at /48 two octets go before the gap and two behind it");
Expect(Pref64.Embed(IPAddress.Parse("2001:db8:100::"), 56, v4).Equals(IPAddress.Parse("2001:db8:100:c0:0:221::")),
    "at /56 one octet goes before the gap and three behind it");
Expect(Pref64.Embed(IPAddress.Parse("2001:db8:100::"), 64, v4).Equals(IPAddress.Parse("2001:db8:100::c0:2:2100:0")),
    "at /64 the whole address sits behind the gap");
foreach (var len in Pref64.PrefixLengths)
{
    var prefix = IPAddress.Parse(len == 96 ? "64:ff9b::" : "2001:db8:100::");
    var embedded = Pref64.Embed(prefix, len, v4);
    Expect(Pref64.Extract(prefix, len, embedded) is { } back && back.Equals(v4),
        $"so the /{len} embedding reads back as the address it was built from");
}
var embedded48 = Pref64.Embed(IPAddress.Parse("2001:db8:100::"), 48, v4);
var withReserved = embedded48.GetAddressBytes();
withReserved[8] = 0x01;
Expect(Pref64.Extract(IPAddress.Parse("2001:db8:100::"), 48, new IPAddress(withReserved)) is null,
    "an address carrying a non-zero octet 8 is not an embedding, so reading it back is a refusal");
var withTail = embedded48.GetAddressBytes();
withTail[12] = 0x80;
Expect(Pref64.Extract(IPAddress.Parse("2001:db8:100::"), 48, new IPAddress(withTail)) is null,
    "and neither is one with bits set behind the embedded address");
Expect(Pref64.Extract(IPAddress.Parse("2001:db8:200::"), 48, embedded48) is null,
    "an address under a different prefix is not this prefix's embedding");
Expect(Pref64.Extract(IPAddress.Parse("64:ff9b::"), 96, IPAddress.Parse("192.0.2.33")) is null,
    "and an IPv4 address is never read as an embedded one");

// A second vector whose every octet has its high bit set: with 192.0.2.33 the bit each straddling length
// puts at octet 8 is a zero, so an embed that writes there looks identical to one that skips it. This
// vector makes the gap observable at every length that crosses it, whatever the address's bits are.
var v4High = IPAddress.Parse("255.254.253.252");
foreach (var len in Pref64.PrefixLengths)
{
    var prefix = IPAddress.Parse(len == 96 ? "64:ff9b::" : "2001:db8:100::");
    var bytes = Pref64.Embed(prefix, len, v4High).GetAddressBytes();
    Expect(len == 96 || bytes[8] == 0,
        $"the /{len} embedding of an all-high-bits address still leaves octet 8 zero");
    Expect(Pref64.Extract(prefix, len, new IPAddress(bytes)) is { } back && back.Equals(v4High),
        $"and reads back through the gap at /{len}");
}

// --- The state an address has to be in before a socket can go on it ---------------------------------
// RFC 4862 §5.4: an address under Duplicate Address Detection "is said to be tentative until the procedure
// has completed successfully", and a bind two milliseconds after New-NetIPAddress returned on this host's
// Ethernet answered that address with WSAEADDRNOTAVAIL (measured 2026-11-01). Host.WaitUsableAddress polls
// again only while the state reads Tentative and otherwise reports what it got, so the bar it treats as
// usable is stated here rather than left to the next elevated run. The five names are the members of the
// enum this host's cmdlet returns (measured: Invalid, Tentative, Duplicate, Deprecated, Preferred), and both
// of the states below that stop the wait took a bind on this host's Ethernet the same day.
Expect(Host.IsUsable("Preferred"), "a Preferred address is one to put a listener on");
Expect(Host.IsUsable("Deprecated"),
    "and so is a Deprecated one: §5.4's bar is the tentative state, and this host's Deprecated link-local took a bind");
foreach (var notYet in new[] { "Tentative", "Duplicate", "Invalid" })
    Expect(!Host.IsUsable(notYet), $"a {notYet} address is not one to put a listener on");
Expect(!Host.IsUsable(null), "no row at all is not a usable state either, so the caller sees the absence rather than a state");


// --- RFC 7915's stateless IP/ICMP translation ------------------------------------------------------------
// Every packet here is laid out octet by octet, and every checksum is computed a second time from the
// standard's own figure - §5.1 and §4.1's field pairing, §5.2 and §4.2's type and code tables, Figures 6 and
// 3's pointer maps, RFC 4884's length attribute, RFC 791 §3.1 and RFC 8200 §8.1's pseudo-headers - so a
// mistake in Siit.cs cannot agree with a copy of itself.
var siitPref = new Pref64Config(IPAddress.Parse("64:ff9b::"), 96);
var nat64 = Siit.FromPrefix(siitPref);
var unknownMtu = Siit.PathMtu.Unknown;
const string V4A = "192.0.2.1";
const string V4B = "203.0.113.9";
const string V6A = "64:ff9b::192.0.2.1";
const string V6B = "64:ff9b::203.0.113.9";

// A caller's table instead of the prefix, which is how RFC 6146's BIB and STE entries will feed the same
// function: §4.3's and §5.3's "The translation of the inner IP header can be done by invoking the function
// that translated the outer IP headers" is the mapping handed in, and it answers for both legs at once.
Siit.AddressMap Table(string fromA, string toA, string fromB, string toB) =>
    (IPAddress source, IPAddress destination, out IPAddress? mappedSource, out IPAddress? mappedDestination) =>
    {
        mappedSource = source.Equals(IPAddress.Parse(fromA)) ? IPAddress.Parse(toA) : null;
        mappedDestination = destination.Equals(IPAddress.Parse(fromB)) ? IPAddress.Parse(toB) : null;
        return mappedSource is not null && mappedDestination is not null;
    };
var stateful = Table(v6Source, V4A, V6B, V4B);
var linkLocalMap = Table("fe80::1", V4A, V6B, V4B);

// RFC 1071 §1's sum, and the property §1(B) states with it: a message whose checksum field is correct sums,
// that field read as it stands, to all ones.
uint Folded(params byte[][] parts)
{
    var all = new List<byte>();
    foreach (var part in parts) all.AddRange(part);
    var sum = 0u;
    for (var i = 0; i < all.Count; i += 2)
    {
        var word = (uint)all[i] << 8;
        if (i + 1 < all.Count) word |= all[i + 1];
        sum += word;
    }
    while (sum > 0xFFFF) sum = (sum & 0xFFFF) + (sum >> 16);
    return sum;
}
ushort OnesComplement(params byte[][] parts) => (ushort)~Folded(parts);
bool ChecksumOk(params byte[][] parts) => Folded(parts) == 0xFFFF;

// RFC 9293 §3.1's figure 2 and RFC 8200 §8.1's, the two pseudo-headers a transport checksum runs over.
byte[] PseudoFour(byte[] source, byte[] destination, byte protocol, int length)
{
    var pseudo = new byte[12];
    source.CopyTo(pseudo, 0);
    destination.CopyTo(pseudo, 4);
    pseudo[9] = protocol;
    BinaryPrimitives.WriteUInt16BigEndian(pseudo.AsSpan(10), (ushort)length);
    return pseudo;
}
byte[] PseudoSix(byte[] source, byte[] destination, byte nextHeader, int length)
{
    var pseudo = new byte[40];
    source.CopyTo(pseudo, 0);
    destination.CopyTo(pseudo, 16);
    BinaryPrimitives.WriteUInt32BigEndian(pseudo.AsSpan(32), (uint)length);
    pseudo[39] = nextHeader;
    return pseudo;
}

byte[] V6Datagram(byte next, string source, string destination, byte hopLimit, byte trafficClass, byte[] payload)
{
    var packet = new byte[40 + payload.Length];
    packet[0] = (byte)(0x60 | (trafficClass >> 4));
    packet[1] = (byte)((trafficClass & 0x0F) << 4);
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4), (ushort)payload.Length);
    packet[6] = next;
    packet[7] = hopLimit;
    AddressOf(source).CopyTo(packet, 8);
    AddressOf(destination).CopyTo(packet, 24);
    payload.CopyTo(packet, 40);
    return packet;
}

byte[] V4Datagram(byte protocol, string source, string destination, byte ttl, ushort id, ushort flags,
    byte[] transport, byte[]? options = null, byte tos = 0)
{
    var headerLength = 20 + (options?.Length ?? 0);
    var packet = new byte[headerLength + transport.Length];
    packet[0] = (byte)(0x40 | headerLength / 4);
    packet[1] = tos;
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), (ushort)packet.Length);
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4), id);
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(6), flags);
    packet[8] = ttl;
    packet[9] = protocol;
    AddressOf(source).CopyTo(packet, 12);
    AddressOf(destination).CopyTo(packet, 16);
    options?.CopyTo(packet, 20);
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(10), OnesComplement(packet[..headerLength]));
    transport.CopyTo(packet, headerLength);
    return packet;
}

// RFC 8200 §4.5's header: the next header it names, the 13-bit offset in 8-octet units with the M flag after
// it, and the 32-bit Identification.
byte[] FragmentHeader(byte next, int offsetUnits, bool more, uint id)
{
    var header = new byte[8];
    header[0] = next;
    BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(2), (ushort)((offsetUnits << 3) | (more ? 1 : 0)));
    BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4), id);
    return header;
}

byte[] UdpMessage(ushort sport, ushort dport, byte[] data, byte[] source, byte[] destination, bool v6,
    int checksumLength)
{
    var message = new byte[8 + data.Length];
    BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(0), sport);
    BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(2), dport);
    BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(4), (ushort)message.Length);
    data.CopyTo(message, 8);
    var pseudo = v6 ? PseudoSix(source, destination, 17, checksumLength)
        : PseudoFour(source, destination, 17, checksumLength);
    BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(6), OnesComplement(pseudo, message));
    return message;
}

byte[] TcpMessage(ushort sport, ushort dport, byte[] data, byte[] source, byte[] destination, bool v6,
    int checksumLength)
{
    var message = new byte[20 + data.Length];
    BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(0), sport);
    BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(2), dport);
    message[12] = 0x50;
    message[13] = 0x02;
    BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(14), 65535);
    data.CopyTo(message, 20);
    var pseudo = v6 ? PseudoSix(source, destination, 6, checksumLength)
        : PseudoFour(source, destination, 6, checksumLength);
    BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(16), OnesComplement(pseudo, message));
    return message;
}

// The same message with its checksum field cleared, which is what the checksum is computed over.
byte[] Unsigned(byte[] transport, int field)
{
    var copy = (byte[])transport.Clone();
    BinaryPrimitives.WriteUInt16BigEndian(copy.AsSpan(field), 0);
    return copy;
}

// RFC 792 §1's and RFC 4443 §2.3's message: eight octets of header, the second word its type names, then the
// quoted datagram and whatever sits behind it.
byte[] IcmpSix(byte type, byte code, byte[] secondWord, byte[] body, byte[] source, byte[] destination)
{
    var message = new byte[8 + body.Length];
    message[0] = type;
    message[1] = code;
    secondWord.CopyTo(message, 4);
    body.CopyTo(message, 8);
    BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(2),
        OnesComplement(PseudoSix(source, destination, 58, message.Length), message));
    return message;
}

byte[] IcmpFour(byte type, byte code, byte[] secondWord, byte[] body)
{
    var message = new byte[8 + body.Length];
    message[0] = type;
    message[1] = code;
    secondWord.CopyTo(message, 4);
    body.CopyTo(message, 8);
    BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(2), OnesComplement(message));
    return message;
}

(bool Ok, byte[]? Packet, string Why) Down64(byte[] packet, Siit.AddressMap? map = null, ushort id = 0x1234,
    Siit.PathMtu? path = null)
{
    var ok = Siit.TryV6ToV4(packet, map ?? nat64, id, path ?? unknownMtu, out var translated, out var why);
    return (ok, translated, why);
}

(bool Ok, byte[]? Packet, string Why) Up46(byte[] packet, Siit.AddressMap? map = null, Siit.PathMtu? path = null)
{
    var ok = Siit.TryV4ToV6(packet, map ?? nat64, path ?? unknownMtu, out var translated, out var why);
    return (ok, translated, why);
}

Expect(Siit.MinimumIpv6Mtu == 1280 && Siit.Ipv4DfThreshold == 1260,
    "§5's two figures: \"An IPv6 link has to have an MTU of 1280 bytes or greater\", and the Don't Fragment rule that turns on that less its own 20-octet header");
Expect(Siit.IsTranslatable(IPAddress.Parse(V6B), siitPref),
    "§5.6's question about 64:ff9b::203.0.113.9 answers yes: it is a member of the /96");
Expect(!Siit.IsTranslatable(IPAddress.Parse(v6Source), siitPref),
    "and a client's own address in the delegated prefix is not one");

// IPv6 to IPv4, field by field against §5.1's list.
var eightBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
var udpV6 = UdpMessage(12345, 443, eightBytes, AddressOf(V6A), AddressOf(V6B), v6: true, checksumLength: 16);
var plainV6 = V6Datagram(17, V6A, V6B, 64, 0xa4, udpV6);
var down = Down64(plainV6);
var d = down.Packet;
Expect(down.Ok && d is not null, "an IPv6 UDP datagram whose pair the /96 mapping reaches translates (§5.1)");
Expect(d is not null && d[0] == 0x45,
    "§5.1's Version 4 and Internet Header Length: 4 and 5, since this translation puts no IPv4 option in the header");
Expect(d is not null && d[1] == 0xa4,
    "the TOS octet takes the IPv6 Traffic Class, which RFC 8200 §3 splits across the nibbles of octets 1 and 2");
Expect(d is not null && BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(2)) == (ushort)(20 + udpV6.Length),
    "Total Length is RFC 791 §3.1's figure for the header and the datagram it now carries");
Expect(d is not null && BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(4)) == 0x1234,
    "§5.1's \"Set according to a Fragment Identification generator at the translator\": the generator's value is the caller's");
Expect(d is not null && (BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(6)) & 0x4000) == 0,
    "48 bytes is smaller than or equal to §5's 1260, so \"the translator MUST send the packet with a cleared Don't Fragment bit\"");
Expect(d is not null && d[8] == 63, "§5.1 has the translator decrement the Hop Limit as any router would");
Expect(d is not null && d[9] == 17, "§5.1's Protocol row copies the next header the walk stopped at");
Expect(d is not null && d.AsSpan(12, 4).SequenceEqual(AddressOf(V4A)) && d.AsSpan(16, 4).SequenceEqual(AddressOf(V4B)),
    "the two addresses are the RFC 6052 §5 embeddings read back out of the /96");
Expect(d is not null && ChecksumOk(d[..20]), "§5.1's \"Header Checksum: Computed once the IPv4 header has been created\"");
Expect(d is not null && ChecksumOk(PseudoFour(AddressOf(V4A), AddressOf(V4B), 17, 16), d[20..]),
    "§5.5's MUST for UDP: the checksum is the one an IPv4 host computes over RFC 791 §3.1's pseudo-header, with the header it now sits behind");
Expect(d is not null && d.AsSpan(28).SequenceEqual(eightBytes)
       && BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(24)) == 16,
    "the datagram's octets and its own length field ride along untouched");

var smallData = new byte[1232];
var justOver = new byte[1233];
Expect(d is not null
       && (BinaryPrimitives.ReadUInt16BigEndian(Down64(V6Datagram(17, V6A, V6B, 64, 0,
               UdpMessage(1, 2, smallData, AddressOf(V6A), AddressOf(V6B), true, 1240))).Packet!.AsSpan(6)) & 0x4000) == 0,
    "a translated packet of exactly 1260 octets keeps DF cleared, which is §5's \"smaller than or equal to 1260 bytes\"");
Expect((BinaryPrimitives.ReadUInt16BigEndian(Down64(V6Datagram(17, V6A, V6B, 64, 0,
        UdpMessage(1, 2, justOver, AddressOf(V6A), AddressOf(V6B), true, 1241))).Packet!.AsSpan(6)) & 0x4000) != 0,
    "and one octet over the figure MUST set the Don't Fragment bit");

var hopOne = Down64(V6Datagram(17, V6A, V6B, 1, 0, udpV6));
Expect(!hopOne.Ok && hopOne.Why.Contains("§5.1"),
    "a Hop Limit of 1 stops at §5.1's \"the translator (as any router) MUST check for zero and send the ICMPv4 'TTL Exceeded' ... error\"");
Expect(!Down64(V6Datagram(17, V6A, V6B, 0, 0, udpV6)).Ok, "and so does a Hop Limit of 0");
foreach (var illegalSource in new[] { "::1", "fe80::1", "ff02::1", "::" })
{
    var rejected = Down64(V6Datagram(17, illegalSource, V6B, 64, 0, udpV6));
    Expect(!rejected.Ok && rejected.Why.Contains("router forwards"),
        $"a source of {illegalSource} is one RFC 4291 keeps a router from forwarding a packet from, and §5.1 silently drops it");
}
var fromLinkLocal = Down64(V6Datagram(58, "fe80::1", V6B, 255, 0,
    IcmpSix(128, 0, new byte[4], eightBytes, AddressOf("fe80::1"), AddressOf(V6B))), linkLocalMap);
Expect(fromLinkLocal.Ok && fromLinkLocal.Packet is not null && fromLinkLocal.Packet[20] == 8,
    "an ICMPv6 message is not dropped for its source being link-local: §4.1's note is that \"when translating ICMPv4 Error Messages into ICMPv6, the 'illegal' source address will be translated for the purpose of trouble shooting\"");
var unmapped = Down64(V6Datagram(17, v6Source, V6B, 64, 0, udpV6));
Expect(!unmapped.Ok && unmapped.Why.Contains("does not reach"),
    "a source the mapping does not reach stops the translation, which is the state a stateless §5 translator has none of");
var viaTable = Down64(V6Datagram(17, v6Source, V6B, 64, 0, udpV6), stateful);
Expect(viaTable.Ok && viaTable.Packet is not null
       && viaTable.Packet.AsSpan(12, 4).SequenceEqual(AddressOf(V4A)),
    "the same function over a caller's table: a client outside the prefix translates to whatever its entry answers");

// §5.1.1's Fragment Header rows, and the octets of a fragment that has no transport header of its own.
var laterFragment = new byte[] { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
var laterPacket = V6Datagram(44, V6A, V6B, 64, 0, Chain(FragmentHeader(17, 185, false, 0x0000abcd), laterFragment));
var downFrag = Down64(laterPacket);
var df = downFrag.Packet;
Expect(downFrag.Ok && df is not null && (BinaryPrimitives.ReadUInt16BigEndian(df.AsSpan(6)) & 0x1FFF) == 185,
    "§5.1.1's \"Fragment Offset MUST be copied from the Fragment Offset field of the IPv6 Fragment Header\", and both count 8-octet units");
Expect(df is not null && (BinaryPrimitives.ReadUInt16BigEndian(df.AsSpan(6)) & 0x2000) == 0,
    "the M flag, clear, copies as More Fragments clear");
Expect(df is not null && (BinaryPrimitives.ReadUInt16BigEndian(df.AsSpan(6)) & 0x4000) == 0,
    "§5.1.1: \"The IPv4 Don't Fragment (DF) flag is cleared (set to zero), allowing this packet to be further fragmented by IPv4 routers\"");
Expect(df is not null && BinaryPrimitives.ReadUInt16BigEndian(df.AsSpan(4)) == 0xabcd,
    "§5.1.1's \"Identification: Copied from the low-order 16 bits in the Identification field in the Fragment Header\"");
Expect(df is not null && df[9] == 17 && df.Length == 30,
    "§5.1's Protocol row takes the number from the last IPv6 header, and a fragment other than the first has no header of its own for the translator to rewrite");
Expect(df is not null && df.AsSpan(20).SequenceEqual(laterFragment),
    "the fragment's octets start where the IPv4 header ends, since there is no transport header in front of them");

var downM = Down64(V6Datagram(44, V6A, V6B, 64, 0, Chain(FragmentHeader(17, 0, true, 0x12345678), udpV6)));
Expect(downM.Ok && downM.Packet is not null
       && (BinaryPrimitives.ReadUInt16BigEndian(downM.Packet.AsSpan(6)) & 0x2000) != 0
       && BinaryPrimitives.ReadUInt16BigEndian(downM.Packet.AsSpan(4)) == 0x5678,
    "a set M flag copies to MF, and the 32-bit Identification gives its low sixteen bits and no more");

var behindFragment = V6Datagram(44, V6A, V6B, 64, 0, Chain(FragmentHeader(51, 0, true, 1), laterFragment));
Expect(!Down64(behindFragment).Ok && Down64(behindFragment).Why.Contains("§5.1.1"),
    "§5.1.1: \"If the Next Header field of the Fragment Header is an extension header (except ESP, but including the Authentication Header (AH)), then the packet SHOULD be dropped and logged\"");
var espFragment = Down64(V6Datagram(44, V6A, V6B, 64, 0, Chain(FragmentHeader(50, 0, true, 1), laterFragment)));
Expect(espFragment.Ok && espFragment.Packet is not null && espFragment.Packet[9] == 50,
    "ESP is the exception §5.1.1 names, so its number is the one copied to the protocol field");

var tcpFirst = TcpMessage(12345, 443, new byte[] { 0x30, 0x39 }, AddressOf(V6A), AddressOf(V6B), v6: true, 22);
Expect(Down64(V6Datagram(0, V6A, V6B, 64, 0,
        Chain(new byte[] { 60, 0, 0, 0, 0, 0, 0, 0 }, new byte[] { 6, 0, 0, 0, 0, 0, 0, 0 }, tcpFirst))).Packet is { } afterChain
       && afterChain[9] == 6,
    "§5.1 skips HOPOPT and IPv6-Opts \"as they have no meaning in IPv4\" and copies the transport number it stops at");
var routingUsed = Down64(V6Datagram(43, V6A, V6B, 64, 0,
    Chain(new byte[] { 6, 0, 0, 1, 0, 0, 0, 0 }, tcpFirst)));
Expect(!routingUsed.Ok && routingUsed.Why.Contains("octet 43"),
    "§5.1: \"If a Routing header with a non-zero Segments Left field is present, then the packet MUST NOT be translated\", and the Parameter Problem it asks for points at RFC 8200 §4.4.1's Segments Left octet");
Expect(Down64(V6Datagram(43, V6A, V6B, 64, 0,
        Chain(new byte[] { 6, 0, 0, 0, 0, 0, 0, 0 }, tcpFirst))).Packet is { } routed && routed[9] == 6,
    "the same header with Segments Left 0 is one §5.1 steps over");
var noNext = Down64(V6Datagram(59, V6A, V6B, 64, 0, new byte[0]));
Expect(!noNext.Ok && noNext.Why.Contains("59"),
    "RFC 8200 §4.7's No Next Header (59) \"indicates that there is nothing following that header\", so there is no datagram to hand over");
Expect(Down64(V6Datagram(47, V6A, V6B, 64, 0, new byte[] { 0, 0, 0, 1, 2, 3 })).Packet is { } gre && gre[9] == 47,
    "§5.1: \"This means that all transport protocols are translated\" - a protocol with no checksum field is copied octet for octet");

var overclaimed = V6Datagram(17, V6A, V6B, 64, 0, udpV6);
BinaryPrimitives.WriteUInt16BigEndian(overclaimed.AsSpan(4), (ushort)(udpV6.Length + 100));
Expect(!Down64(overclaimed).Ok && Down64(overclaimed).Why.Contains("payload length"),
    "a Payload Length that claims more than the datagram on hand holds is not one to translate (RFC 8200 §3)");
var zeroChecksum6 = Down64(V6Datagram(17, V6A, V6B, 64, 0, Unsigned(udpV6, 6)));
Expect(!zeroChecksum6.Ok && zeroChecksum6.Why.Contains("RFC 8200 §8.1"),
    "RFC 8200 §8.1: \"IPv6 receivers must discard UDP packets containing a zero checksum and should log the error\"");

// A first fragment is the case where the rest of the datagram never comes through here, so the stored
// checksum can only be moved by the words that changed. The whole message is known in this file, which is
// what makes the check: the value written has to be the one the far host computes over the reassembled one.
var wholeData = new byte[40];
for (var i = 0; i < wholeData.Length; i++) wholeData[i] = (byte)(0x40 + i);
var wholeUdp6 = UdpMessage(5000, 5001, wholeData, AddressOf(V6A), AddressOf(V6B), v6: true, checksumLength: 48);
var downFirst = Down64(V6Datagram(44, V6A, V6B, 64, 0,
    Chain(FragmentHeader(17, 0, true, 0x00000a0b), wholeUdp6[..28])));
var folded = downFirst.Packet is not null ? BinaryPrimitives.ReadUInt16BigEndian(downFirst.Packet.AsSpan(26)) : (ushort)0;
Expect(downFirst.Ok && folded == OnesComplement(PseudoFour(AddressOf(V4A), AddressOf(V4B), 17, 48), Unsigned(wholeUdp6, 6)),
    "the value it writes is the checksum the far host computes over the reassembled IPv4 datagram: RFC 1624 §2's HC' = ~(C + (-m) + m'), with the unseen octets cancelling");
Expect(folded == BinaryPrimitives.ReadUInt16BigEndian(wholeUdp6.AsSpan(6)),
    "and for this pair of addresses it is the same octets as the ones that arrived, because RFC 6052 §5's embedding puts the IPv4 words inside the IPv6 ones and 64:ff9b's two add to RFC 1071's all-ones, so RFC 8200 §8.1's pseudo-header and RFC 791 §3.1's sum to the same value");

// The same fold with a source the prefix mapping cannot reach, where the two pseudo-headers genuinely differ.
var tableUdp6 = UdpMessage(5000, 5001, wholeData, AddressOf(v6Source), AddressOf(V6B), v6: true, checksumLength: 48);
var downTableFirst = Down64(V6Datagram(44, v6Source, V6B, 64, 0,
    Chain(FragmentHeader(17, 0, true, 0x00000a0b), tableUdp6[..28])), stateful);
var foldedAcrossTable = downTableFirst.Packet is not null
    ? BinaryPrimitives.ReadUInt16BigEndian(downTableFirst.Packet.AsSpan(26)) : (ushort)0;
Expect(downTableFirst.Ok && foldedAcrossTable != BinaryPrimitives.ReadUInt16BigEndian(tableUdp6.AsSpan(6)),
    "a source that is not the destination's own embedding moves the field, which is the case the fold exists for");
Expect(downTableFirst.Ok
       && foldedAcrossTable == OnesComplement(PseudoFour(AddressOf(V4A), AddressOf(V4B), 17, 48), Unsigned(tableUdp6, 6)),
    "and it lands on the value the IPv4 receiver verifies over the reassembled datagram, the unseen 20 octets having cancelled out of both sums");

// §5.2's table, message by message.
var echoSix = IcmpSix(128, 0, new byte[] { 0x12, 0x34, 0, 1 }, eightBytes, AddressOf(V6A), AddressOf(V6B));
var echoPacket = V6Datagram(58, V6A, V6B, 64, 0, echoSix);
var downEcho = Down64(echoPacket);
Expect(downEcho.Ok && downEcho.Packet is not null && downEcho.Packet[9] == 1
       && downEcho.Packet[20] == 8 && downEcho.Packet[21] == 0,
    "§5.2's \"Echo Request ... Adjust the Type values to 8\", with §5.1's Protocol row changing 58 to 1");
Expect(downEcho.Packet is not null
       && downEcho.Packet.AsSpan(24, 4).SequenceEqual(new byte[] { 0x12, 0x34, 0, 1 })
       && downEcho.Packet.AsSpan(28).SequenceEqual(eightBytes),
    "RFC 792 §1.9's Identifier and Sequence Number stay in the second word and the payload rides along");
Expect(downEcho.Packet is not null && ChecksumOk(downEcho.Packet[20..]),
    "§5.2: the checksum is adjusted \"to exclude the ICMPv6 pseudo-header\", so it verifies over the message alone");
Expect(downEcho.Packet is not null
       && BinaryPrimitives.ReadUInt16BigEndian(downEcho.Packet.AsSpan(22))
          != BinaryPrimitives.ReadUInt16BigEndian(echoSix.AsSpan(2)),
    "and it is a different value from the IPv6 one, since the pseudo-header that was in the sum is now out of it");
Expect(Down64(V6Datagram(58, V6A, V6B, 64, 0,
        IcmpSix(129, 0, new byte[4], eightBytes, AddressOf(V6A), AddressOf(V6B)))).Packet is { } echoReply
       && echoReply[20] == 0,
    "§5.2: Echo Reply (129) becomes Type 0");
var neighbour = Down64(V6Datagram(58, V6A, V6B, 255, 0, IcmpSix(133, 0, new byte[4], eightBytes, AddressOf(V6A), AddressOf(V6B))));
Expect(!neighbour.Ok && neighbour.Why.Contains("§5.2"),
    "§5.2: \"Neighbor Discover messages (Type 133 through 137): Single-hop message. Silently drop.\"");
Expect(!Down64(V6Datagram(58, V6A, V6B, 255, 0, IcmpSix(131, 0, new byte[4], eightBytes, AddressOf(V6A), AddressOf(V6B)))).Ok,
    "and MLD's types 130 through 132 with them");

var inner6 = V6Datagram(17, V6A, V6B, 7, 0,
    UdpMessage(12345, 443, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 },
        AddressOf(V6A), AddressOf(V6B), v6: true, checksumLength: 20));
var opaqueTail = new byte[] { 0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44 };
var downUnreachable = Down64(V6Datagram(58, V6B, V6A, 250, 0,
    IcmpSix(1, 4, new byte[4], Chain(inner6, opaqueTail), AddressOf(V6B), AddressOf(V6A))));
var du = downUnreachable.Packet;
Expect(downUnreachable.Ok && du is not null && du[20] == 3 && du[21] == 3,
    "§5.2: \"Destination Unreachable (Type 1) Set the Type to 3\", and its \"Code 4 (Port unreachable): Set the Code to 3\"");
Expect(du is not null && du[28] == 0x45 && du[37] == 17,
    "§5.2's \"for ICMP error messages, the included IP header MUST also be translated\", which §5.3 has this same function do");
Expect(du is not null && BinaryPrimitives.ReadUInt16BigEndian(du.AsSpan(30)) == 40 && ChecksumOk(du[28..48]),
    "§5.3: \"the Total Length field in the outer IPv4 header MUST be updated\" - the 20-octet header plus the 20 octets of transport the sender quoted - and its header checksum with it");
Expect(du is not null && du[36] == 7,
    "§5.3's exception holds: \"the TTL/Hop Limit value of the inner IPv4/IPv6 packet are not decremented\"");
Expect(du is not null && du.AsSpan(56, 12).SequenceEqual(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }),
    "the transport octets inside the quote are the sender's, which is all Figures 6's and 7's \"Partial Transport-Layer Header\" box holds");
Expect(du is not null && du.AsSpan(68, 8).SequenceEqual(opaqueTail),
    "§5.2's ICMP Error Payload paragraph passes extensions along \"as opaque bit strings\", and they sit behind the quote as they did in front of it");
Expect(du is not null && ChecksumOk(du[20..]), "and the translated message's own ICMPv4 checksum verifies");
Expect(du is not null && du[25] == 0,
    "RFC 4884 §5.4: a zero length attribute says \"the message contains no extensions\", and this one carried none");

// §5.3's drop counts embedded headers, and the two quoted messages differ exactly there: an error carries
// another quoted IP header behind its own, a query carries none. RFC 6146 §3.4's third bullet draws the same
// line for the stateful translator, calling the error-containing-a-query a packet whose 3-tuple is computed.
var quotingQuery = Down64(V6Datagram(58, V6B, V6A, 250, 0,
    IcmpSix(1, 1, new byte[4], echoPacket, AddressOf(V6B), AddressOf(V6A))));
Expect(quotingQuery.Ok && quotingQuery.Packet is not null && quotingQuery.Packet[20] == 3
       && quotingQuery.Packet[28] == 0x45,
    "an error quoting a query has one embedded header, so §5.3 translates it - the quoted Echo Request becoming the ICMPv4 packet the IPv4 receiver asked for");
Expect(quotingQuery.Packet is not null && ChecksumOk(quotingQuery.Packet[20..]),
    "and the message with the query inside it still carries a checksum that verifies over the ICMPv4 alone");
var quotingError = Down64(V6Datagram(58, V6B, V6A, 250, 0,
    IcmpSix(1, 1, new byte[4],
        V6Datagram(58, V6A, V6B, 64, 0,
            IcmpSix(2, 0, new byte[] { 0, 0, 5, 0x8c }, echoPacket, AddressOf(V6A), AddressOf(V6B))),
        AddressOf(V6B), AddressOf(V6A))));
Expect(!quotingError.Ok && quotingError.Why.Contains("§5.3"),
    "§5.3: \"This process MUST stop at the first embedded header and drop the packet if it contains more embedded headers\" - a quoted Packet Too Big carries its own quoted IP header, which is the second level");

var downPtb = Down64(V6Datagram(58, V6B, V6A, 250, 0,
    IcmpSix(2, 0, UInt32(1500), inner6, AddressOf(V6B), AddressOf(V6A))), path: new Siit.PathMtu(1492, 1492));
Expect(downPtb.Ok && downPtb.Packet is not null && downPtb.Packet[20] == 3 && downPtb.Packet[21] == 4,
    "§5.2: \"Packet Too Big (Type 2): Translate to an ICMPv4 Destination Unreachable (Type 3) with Code 4\"");
Expect(downPtb.Packet is not null && BinaryPrimitives.ReadUInt16BigEndian(downPtb.Packet.AsSpan(26)) == 1472,
    "§5.2's minimum((MTU)-20, MTU_of_IPv4_nexthop, (MTU_of_IPv6_nexthop)-20) = minimum(1480, 1492, 1472)");
Expect(Down64(V6Datagram(58, V6B, V6A, 250, 0,
        IcmpSix(2, 0, UInt32(1500), inner6, AddressOf(V6B), AddressOf(V6A)))).Packet is { } ptbUnknown
       && BinaryPrimitives.ReadUInt16BigEndian(ptbUnknown.AsSpan(26)) == 1480,
    "with neither next-hop MTU known the formula's own figure is all that is left, and §5.2's -20 for the header that went the other way still applies");

var downPointer = Down64(V6Datagram(58, V6B, V6A, 250, 0,
    IcmpSix(4, 0, new byte[] { 6, 0, 0, 0 }, inner6, AddressOf(V6B), AddressOf(V6A))));
Expect(downPointer.Ok && downPointer.Packet is not null && downPointer.Packet[20] == 12 && downPointer.Packet[21] == 0,
    "§5.2: \"Code 0 (Erroneous header field encountered): Set to Type 12, Code 0\"");
Expect(downPointer.Packet is not null && downPointer.Packet[24] == 9,
    "Figure 6 takes a pointer at the IPv6 Next Header octet to the IPv4 Protocol octet");
// Figure 6 row by row, its two address ranges' boundaries (23 and 24) included, and the octets it marks n/a
// or leaves out entirely - the §5.2 sentence "If the Original IPv6 Pointer Value is not listed or the Translated
// IPv4 Pointer Value is listed as 'n/a', silently drop the packet".
foreach (var (octet, translated) in new (byte, byte)[]
    { (0, 0), (1, 1), (4, 2), (5, 2), (7, 8), (8, 12), (23, 12), (24, 16), (39, 16) })
    Expect(Down64(V6Datagram(58, V6B, V6A, 250, 0,
        IcmpSix(4, 0, new byte[] { octet, 0, 0, 0 }, inner6, AddressOf(V6B), AddressOf(V6A)))).Packet is { } figureSix &&
        figureSix[24] == translated,
        $"Figure 6's row for IPv6 octet {octet} answers IPv4 octet {translated}");
foreach (var omitted in new byte[] { 2, 3, 40 })
    Expect(!Down64(V6Datagram(58, V6B, V6A, 250, 0,
        IcmpSix(4, 0, new byte[] { omitted, 0, 0, 0 }, inner6, AddressOf(V6B), AddressOf(V6A)))).Ok,
        $"§5.2 drops a pointer Figure 6 marks n/a or does not list - IPv6 octet {omitted}");
Expect(Down64(V6Datagram(58, V6B, V6A, 250, 0,
        IcmpSix(4, 1, new byte[4], inner6, AddressOf(V6B), AddressOf(V6A)))).Packet is { } protocolProblem
       && protocolProblem[20] == 3 && protocolProblem[21] == 2,
    "§5.2: \"Code 1 (Unrecognized Next Header type encountered): Translate this to an ICMPv4 protocol unreachable (Type 3, Code 2)\"");
Expect(!Down64(V6Datagram(58, V6B, V6A, 250, 0,
    IcmpSix(4, 2, new byte[4], inner6, AddressOf(V6B), AddressOf(V6A)))).Ok,
    "§5.2: \"Code 2 (Unrecognized IPv6 option encountered): Silently drop\"");

var downTime = Down64(V6Datagram(58, V6B, V6A, 250, 0,
    IcmpSix(3, 0, new byte[] { 8, 0, 0, 0 }, Chain(inner6, new byte[4]), AddressOf(V6B), AddressOf(V6A))));
Expect(downTime.Ok && downTime.Packet is not null && downTime.Packet[20] == 11 && downTime.Packet[21] == 0,
    "§5.2: \"Time Exceeded (Type 3): Set the Type to 11 ... The Code is unchanged\"");
Expect(downTime.Packet is not null && downTime.Packet[25] == 10,
    "RFC 4884 §4.5's eight 64-bit words of quote become §4.2's count of 32-bit ones over the quote this translation left: 64 octets promised, 40 translated, ten words");
Expect(downTime.Packet is not null && ChecksumOk(downTime.Packet[20..]),
    "with the checksum computed over the message whose attribute moved");
Expect(Down64(V6Datagram(58, V6B, V6A, 250, 0,
        IcmpSix(3, 1, new byte[] { 8, 0, 0, 0 }, Chain(inner6, new byte[4]), AddressOf(V6B), AddressOf(V6A))))
    .Packet is { } reassembly64 && reassembly64[20] == 11 && reassembly64[21] == 1,
    "code 1 (Fragment Reassembly Time Exceeded) is the code §5.2's \"The Code is unchanged\" has to carry, where the code 0 case cannot tell a copy from a clear");

// §3: "Fragmented ICMP/ICMPv6 packets will not be translated by IP/ICMP translators". A fragment other than the
// first has no Type octet for §5.2's or §4.2's table to read, and a first fragment's message is incomplete.
var fragIcmp6 = Down64(V6Datagram(44, V6B, V6A, 250, 0, Chain(FragmentHeader(58, 0, true, 0x00000001),
    IcmpSix(8, 0, new byte[4], eightBytes, AddressOf(V6B), AddressOf(V6A)))));
Expect(!fragIcmp6.Ok && fragIcmp6.Why.Contains("fragmented ICMP"),
    "an ICMPv6 Echo Request that arrives as the first fragment of a datagram is refused, §3's rule for both directions");
var fragIcmp4 = Up46(V4Datagram(1, V4B, V4A, 250, 0, 0x2000, IcmpFour(8, 0, new byte[4], eightBytes)));
Expect(!fragIcmp4.Ok && fragIcmp4.Why.Contains("fragmented ICMP"),
    "and the same refusal on an ICMPv4 message whose More Fragments flag is set");

// IPv4 to IPv6: §4.1's field list on a TCP segment.
var tenBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
var tcp4 = TcpMessage(12345, 443, tenBytes, AddressOf(V4A), AddressOf(V4B), v6: false, checksumLength: 30);
var up = Up46(V4Datagram(6, V4A, V4B, 64, 0x1111, 0x4000, tcp4));
var u = up.Packet;
Expect(up.Ok && u is not null && u[0] == 0x60 && u[1] == 0,
    "§4.1's \"Version: 6\", a Traffic Class of 0 copied from the TOS octet, and \"Flow Label: 0 (all zero bits)\"");
Expect(u is not null && BinaryPrimitives.ReadUInt16BigEndian(u.AsSpan(4)) == (ushort)tcp4.Length,
    "§4.1's \"Payload Length: Total length value from the IPv4 header, minus the size of the IPv4 header and IPv4 options, if present\"");
Expect(u is not null && u[6] == 6,
    "§4: \"the translator MUST NOT include the Fragment Header for the non-fragmented IPv6 packets\" - DF set is not a fragment");
Expect(u is not null && u[7] == 63, "§4.1's Hop Limit is the TTL, and §4.1's zero check and decrement are the sentence §5.1 repeats");
Expect(u is not null && u.AsSpan(8, 16).SequenceEqual(AddressOf(V6A)) && u.AsSpan(24, 16).SequenceEqual(AddressOf(V6B)),
    "§6's stateless mapping embeds both addresses in the /96");
Expect(u is not null && BinaryPrimitives.ReadUInt16BigEndian(u.AsSpan(40 + 16))
       == OnesComplement(PseudoSix(AddressOf(V6A), AddressOf(V6B), 6, 30), Unsigned(tcp4, 16)),
    "§4.5's MUST for TCP: the checksum is computed over RFC 8200 §8.1's pseudo-header, which is not the one it arrived with");
Expect(u is not null && u.AsSpan(60).SequenceEqual(tenBytes), "and the segment's data is the same octets");

var tosPacket = V4Datagram(6, V4A, V4B, 64, 0, 0, tcp4, tos: 0xef);
Expect(Up46(tosPacket).Packet is { } tosOut && tosOut[0] == (byte)(0x60 | 0x0e) && tosOut[1] == (byte)(0x0f << 4),
    "§4.1's \"Traffic Class: By default, copied from the IP Type Of Service (TOS) octet\", split across the nibbles RFC 8200 §3 uses");

var upFrag = Up46(V4Datagram(6, V4A, V4B, 64, 0xabcd, (ushort)(0x2000 | 185), tenBytes));
var uf = upFrag.Packet;
Expect(upFrag.Ok && uf is not null && uf[6] == 44 && uf[40] == 6,
    "§4.1's fragment case: the base header names the Fragment Header, and its Next Header row copies the IPv4 protocol field");
Expect(uf is not null && (BinaryPrimitives.ReadUInt16BigEndian(uf.AsSpan(42)) & 0xFFF8) == (185 << 3)
       && (uf[43] & 1) == 1,
    "§4.1's \"Fragment Offset: Fragment Offset copied from the IPv4 header\" and \"M flag: More Fragments bit copied from the IPv4 header\", both in 8-octet units");
Expect(uf is not null && BinaryPrimitives.ReadUInt32BigEndian(uf.AsSpan(44)) == 0xabcd,
    "§4.1's \"Identification: The low-order 16 bits copied from the Identification field in the IPv4 header. The high-order 16 bits set to zero\"");
Expect(uf is not null && BinaryPrimitives.ReadUInt16BigEndian(uf.AsSpan(4)) == (ushort)(8 + tenBytes.Length),
    "§4.1's Payload Length carries \"plus 8 for the Fragment Header\" in the fragment case");
Expect(uf is not null && uf.AsSpan(48).SequenceEqual(tenBytes), "and the fragment's own octets follow the header unchanged");

var wholeUdp4 = UdpMessage(5000, 5001, wholeData, AddressOf(V4A), AddressOf(V4B), v6: false, checksumLength: 48);
var upFirst = Up46(V4Datagram(17, V4A, V4B, 64, 0x0a0b, 0x2000, wholeUdp4[..28]));
var upFolded = upFirst.Packet is not null ? BinaryPrimitives.ReadUInt16BigEndian(upFirst.Packet.AsSpan(54)) : (ushort)0;
Expect(upFirst.Ok && upFirst.Packet is not null && upFirst.Packet[6] == 44 && upFirst.Packet[40] == 17,
    "a fragmented IPv4 datagram keeps its Fragment Header in front of the transport it came with");
Expect(upFolded == OnesComplement(PseudoSix(AddressOf(V6A), AddressOf(V6B), 17, 48), Unsigned(wholeUdp4, 6)),
    "the same fold one family over: a first fragment's stored checksum moves by the address words alone and validates at the IPv6 receiver against the reassembled datagram");
var toGlobal = Table(V4A, v6Source, V4B, V6B);
var upTableFirst = Up46(V4Datagram(17, V4A, V4B, 64, 0x0a0b, 0x2000, wholeUdp4[..28]), toGlobal);
var upFoldedAcrossTable = upTableFirst.Packet is not null
    ? BinaryPrimitives.ReadUInt16BigEndian(upTableFirst.Packet.AsSpan(54)) : (ushort)0;
Expect(upTableFirst.Ok && upFoldedAcrossTable != BinaryPrimitives.ReadUInt16BigEndian(wholeUdp4.AsSpan(6))
       && upFoldedAcrossTable == OnesComplement(PseudoSix(AddressOf(v6Source), AddressOf(V6B), 17, 48),
           Unsigned(wholeUdp4, 6)),
    "and mapped to an address outside the embedding, it moves to the value RFC 8200 §8.1's receiver computes over the whole datagram");
var fragmentedZero = Up46(V4Datagram(17, V4A, V4B, 64, 1, 0x2000, Unsigned(wholeUdp4, 6)[..28]));
Expect(!fragmentedZero.Ok && fragmentedZero.Why.Contains("§4.5"),
    "§4.5: \"when a stateless translator receives the first fragment of a fragmented UDP IPv4 packet and the checksum field is zero, the translator SHOULD drop the packet\"");
var unfragmentedZero = Up46(V4Datagram(17, V4A, V4B, 64, 1, 0, Unsigned(wholeUdp4, 6)));
Expect(unfragmentedZero.Ok && unfragmentedZero.Packet is not null
       && BinaryPrimitives.ReadUInt16BigEndian(unfragmentedZero.Packet.AsSpan(46))
          == OnesComplement(PseudoSix(AddressOf(V6A), AddressOf(V6B), 17, 48), Unsigned(wholeUdp4, 6)),
    "an unfragmented one takes §4.5's second configuration choice, \"Calculating an IPv6 checksum and forwarding the packet\", which a stateless translator can do for a whole datagram");

Expect(Up46(V4Datagram(6, V4A, V4B, 64, 0, 0, tcp4, new byte[] { 1, 1, 137, 12, 0, 0, 0, 0, 0, 0, 0, 0 }))
    .Packet is { } withOptions && withOptions[6] == 6 && withOptions.AsSpan(40).SequenceEqual(tcp4),
    "§4.1: \"If any IPv4 options are present in the IPv4 packet, they MUST be ignored and the packet translated normally; there is no attempt to translate the options\"");
var sourceRouted = Up46(V4Datagram(6, V4A, V4B, 64, 0, 0, tcp4, new byte[] { 131, 10, 4, 0, 0, 0, 0, 0, 0, 0 }));
Expect(!sourceRouted.Ok && sourceRouted.Why.Contains("Code 5"),
    "§4.1 keeps the source route out of that rule: \"if an unexpired source route option is present, then the packet MUST instead be discarded, and an ICMPv4 'Destination Unreachable, Source Route Failed' (Type 3, Code 5) error message SHOULD be returned\"");

var badHeader = V4Datagram(6, V4A, V4B, 64, 0, 0, tcp4);
badHeader[10] ^= 0xff;
Expect(!Up46(badHeader).Ok && Up46(badHeader).Why.Contains("checksum"),
    "RFC 791 §3.1's header checksum is what tells a router the header is one to act on, so a header that does not verify is refused");
Expect(!Up46(V4Datagram(6, V4A, V4B, 1, 0, 0, tcp4)).Ok, "§4.1's zero check stops a TTL of 1 before the decrement");
foreach (var illegalSource in new[] { "0.0.0.0", "127.0.0.1", "239.1.2.3", "255.255.255.255" })
{
    var rejected = Up46(V4Datagram(6, illegalSource, V4B, 64, 0, 0, tcp4));
    Expect(!rejected.Ok && rejected.Why.Contains("router forwards"),
        $"a source of {illegalSource} is RFC 1812 §5.3.7's invalid one, which §4.1 silently discards");
}
var lyingV4 = V4Datagram(6, V4A, V4B, 64, 0, 0, tcp4);
BinaryPrimitives.WriteUInt16BigEndian(lyingV4.AsSpan(2), (ushort)(lyingV4.Length + 100));
Expect(!Up46(lyingV4).Ok && Up46(lyingV4).Why.Contains("total length"),
    "a Total Length over the datagram on hand is refused, the way §3's length field is read on the IPv6 side");

// §4.2's table.
var echo4 = IcmpFour(8, 0, new byte[] { 0x12, 0x34, 0, 1 }, eightBytes);
var upEcho = Up46(V4Datagram(1, V4A, V4B, 64, 0, 0, echo4));
Expect(upEcho.Ok && upEcho.Packet is not null && upEcho.Packet[6] == 58 && upEcho.Packet[40] == 128,
    "§4.1's \"For ICMPv4 (1), it is changed to ICMPv6 (58)\" and §4.2's Echo becoming Type 128");
Expect(upEcho.Packet is not null
       && upEcho.Packet.AsSpan(44, 4).SequenceEqual(new byte[] { 0x12, 0x34, 0, 1 })
       && upEcho.Packet.AsSpan(48).SequenceEqual(eightBytes),
    "RFC 792 §1.8's Identifier and Sequence Number and the payload are the same octets in the same places");
Expect(upEcho.Packet is not null && ChecksumOk(PseudoSix(AddressOf(V6A), AddressOf(V6B), 58, upEcho.Packet.Length - 40),
        upEcho.Packet[40..]),
    "§4.2's opening sentence: \"All ICMPv4 messages that are to be translated require that the ICMPv6 checksum field be calculated as part of the translation since ICMPv6, unlike ICMPv4, has a pseudo-header checksum just like UDP and TCP\"");
Expect(upEcho.Packet is not null && BinaryPrimitives.ReadUInt16BigEndian(upEcho.Packet.AsSpan(42))
       != BinaryPrimitives.ReadUInt16BigEndian(echo4.AsSpan(2)),
    "the checksum is a different value from the IPv4 one, which is what adding the pseudo-header and changing the type have to do");

var inner4 = V4Datagram(17, V4A, V4B, 7, 0x2222, 0,
    UdpMessage(12345, 443, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 },
        AddressOf(V4A), AddressOf(V4B), v6: false, checksumLength: 20));
var upUnreachable = Up46(V4Datagram(1, V4B, V4A, 250, 0, 0,
    IcmpFour(3, 3, new byte[4], Chain(inner4, opaqueTail))));
var uu = upUnreachable.Packet;
Expect(upUnreachable.Ok && uu is not null && uu[6] == 58 && uu[40] == 1 && uu[41] == 4,
    "§4.2: Destination Unreachable translated to Type 1, and its \"Code 3 (Port Unreachable): Set the Code to 4\"");
Expect(uu is not null && uu[48] == 0x60 && uu[54] == 17 && uu[55] == 7,
    "§4.3 has the quoted header translated by the same function: version 6, the transport number it carried, and its TTL as the Hop Limit it arrived with");
Expect(uu is not null && BinaryPrimitives.ReadUInt16BigEndian(uu.AsSpan(52)) == 20,
    "and §4.1's Payload Length inside the quote counts its 20 octets of transport");
Expect(uu is not null && BinaryPrimitives.ReadUInt16BigEndian(uu.AsSpan(4)) == (ushort)(uu.Length - 40),
    "the outer Payload Length covers the message's own eight octets, the translated quote and the opaque tail together");
Expect(uu is not null && uu.AsSpan(108, 8).SequenceEqual(opaqueTail),
    "§4.2's ICMP Error Payload paragraph keeps the octets behind the quote as opaque bit strings");
Expect(uu is not null && uu[44] == 0,
    "RFC 4884 §5.4's zero in the ICMPv6 attribute octet says no extensions are guaranteed, which is what this message said on the way in");

// §4.3 states the same count of embedded headers as §5.3, and the same two quoted messages answer it apart.
var upQuotingQuery = Up46(V4Datagram(1, V4B, V4A, 250, 0, 0,
    IcmpFour(3, 1, new byte[4], V4Datagram(1, V4A, V4B, 64, 0, 0, echo4))));
Expect(upQuotingQuery.Ok && upQuotingQuery.Packet is not null
       && upQuotingQuery.Packet[40] == 1 && upQuotingQuery.Packet[48] == 0x60,
    "an ICMPv4 error quoting an Echo Request holds one embedded header, so §4.3 translates it - RFC 6146 §3.4's third bullet reads the same packet as a 3-tuple to compute, not one to discard");
Expect(upQuotingQuery.Packet is not null
       && ChecksumOk(PseudoSix(AddressOf(V6B), AddressOf(V6A), 58, upQuotingQuery.Packet.Length - 40),
           upQuotingQuery.Packet[40..]),
    "and the ICMPv6 checksum covers the message with the translated query inside it, pseudo-header included");
var upQuotingError = Up46(V4Datagram(1, V4B, V4A, 250, 0, 0,
    IcmpFour(3, 4, new byte[] { 0, 0, 5, 0x8c },
        V4Datagram(1, V4A, V4B, 64, 0, 0, IcmpFour(11, 0, new byte[4], inner4)))));
Expect(!upQuotingError.Ok && upQuotingError.Why.Contains("§4.3"),
    "§4.3's drop is the second level: a quoted Time Exceeded carries a quoted IP header of its own behind the first, which is the \"more embedded headers\" the sentence names");
Expect(uu is not null && ChecksumOk(PseudoSix(AddressOf(V6B), AddressOf(V6A), 58, uu.Length - 40), uu[40..]),
    "and the ICMPv6 checksum covers the message with the translated quote inside it");

var upPtb = Up46(V4Datagram(1, V4B, V4A, 250, 0, 0,
    IcmpFour(3, 4, new byte[] { 0, 0, 0x05, 0x78 }, inner4)), path: new Siit.PathMtu(1492, 1492));
Expect(upPtb.Ok && upPtb.Packet is not null && upPtb.Packet[40] == 2 && upPtb.Packet[41] == 0,
    "§4.2: \"Code 4 (Fragmentation Needed and DF was Set): Translate to an ICMPv6 Packet Too Big message (Type 2) with Code set to 0\"");
Expect(upPtb.Packet is not null && BinaryPrimitives.ReadUInt32BigEndian(upPtb.Packet.AsSpan(44)) == 1420,
    "§4.2's maximum(1280, minimum((MTU)+20, MTU_of_IPv6_nexthop, (MTU_of_IPv4_nexthop)+20)) over a reported 1400 and two 1492 next hops = maximum(1280, minimum(1420, 1492, 1512))");
var wideQuote = V4Datagram(17, V4A, V4B, 64, 0, 0,
    UdpMessage(1, 2, new byte[1472], AddressOf(V4A), AddressOf(V4B), v6: false, checksumLength: 1480));
var upPlateau = Up46(V4Datagram(1, V4B, V4A, 250, 0, 0, IcmpFour(3, 4, new byte[4], wideQuote)));
Expect(upPlateau.Ok && upPlateau.Packet is not null
       && BinaryPrimitives.ReadUInt32BigEndian(upPlateau.Packet.AsSpan(44)) == 1492,
    "§4.2's zero-MTU rule takes RFC 1191 §7's greatest plateau under the quoted Total Length of 1500, which is 1492");
var narrowQuote = V4Datagram(17, V4A, V4B, 64, 0, 0,
    UdpMessage(1, 2, new byte[1372], AddressOf(V4A), AddressOf(V4B), v6: false, checksumLength: 1380));
Expect(Up46(V4Datagram(1, V4B, V4A, 250, 0, 0, IcmpFour(3, 4, new byte[4], narrowQuote))).Packet is { } floorOut
       && BinaryPrimitives.ReadUInt32BigEndian(floorOut.AsSpan(44)) == 1280,
    "and with no plateau under 1400 at or above the figure §4.2 says the MTU \"MUST NOT be set\" below, the answer is that figure");

Expect(Up46(V4Datagram(1, V4B, V4A, 250, 0, 0, IcmpFour(3, 2, new byte[4], inner4))).Packet is { } protocolUnreachable
       && protocolUnreachable[40] == 4 && protocolUnreachable[41] == 1 && protocolUnreachable[44] == 6,
    "§4.2: \"Code 2 (Protocol Unreachable): Translate to an ICMPv6 Parameter Problem (Type 4, Code 1) and make the Pointer point to the IPv6 Next Header field\", which RFC 8200 §3 puts at octet 6");
Expect(Up46(V4Datagram(1, V4B, V4A, 250, 0, 0, IcmpFour(3, 1, new byte[4], inner4))).Packet is { } hostUnreachable
       && hostUnreachable[40] == 1 && hostUnreachable[41] == 0,
    "§4.2: \"Code 0, 1 (Net Unreachable, Host Unreachable): Set the Code to 0 (No route to destination)\"");
Expect(Up46(V4Datagram(1, V4B, V4A, 250, 0, 0, IcmpFour(3, 13, new byte[4], inner4))).Packet is { } prohibited
       && prohibited[41] == 1,
    "§4.2: \"Code 13 (Communication Administratively Prohibited): Set the Code to 1\"");
var precedence = Up46(V4Datagram(1, V4B, V4A, 250, 0, 0, IcmpFour(3, 14, new byte[4], inner4)));
Expect(!precedence.Ok && precedence.Why.Contains("drop"),
    "§4.2: \"Code 14 (Host Precedence Violation): Silently drop\"");
Expect(Up46(V4Datagram(1, V4B, V4A, 250, 0, 0, IcmpFour(11, 1, new byte[4], inner4))).Packet is { } timeUp
       && timeUp[40] == 3 && timeUp[41] == 1,
    "§4.2: \"Time Exceeded (Type 11): Set the Type to 3 ... The Code is unchanged\"");
Expect(Up46(V4Datagram(1, V4B, V4A, 250, 0, 0, IcmpFour(12, 0, new byte[] { 9, 0, 0, 0 }, inner4))).Packet is { } pointerUp
       && pointerUp[40] == 4 && pointerUp[44] == 6,
    "Figure 3 takes the IPv4 Protocol octet to the IPv6 Next Header octet");
// Figure 3 row by row, both §4.2's own sentence covering it - "If the Original IPv4 Pointer Value is not listed
// or the Translated IPv6 Pointer Value is listed as 'n/a', silently drop the packet" - and Code 2's reuse of the
// same map, which the row below the sweep's own keeps its place for.
foreach (var (octet, translated) in new (byte, byte)[]
    { (0, 0), (1, 1), (2, 4), (3, 4), (8, 7), (12, 8), (15, 8), (16, 24), (19, 24) })
    Expect(Up46(V4Datagram(1, V4B, V4A, 250, 0, 0, IcmpFour(12, 0, new byte[] { octet, 0, 0, 0 }, inner4)))
        .Packet is { } figureThree && figureThree[44] == translated,
        $"Figure 3's row for IPv4 octet {octet} answers IPv6 octet {translated}");
foreach (var omitted in new byte[] { 4, 5, 6, 7, 10, 11, 20 })
    Expect(!Up46(V4Datagram(1, V4B, V4A, 250, 0, 0, IcmpFour(12, 0, new byte[] { omitted, 0, 0, 0 }, inner4))).Ok,
        $"§4.2 drops a pointer Figure 3 marks n/a or does not list - IPv4 octet {omitted}");
Expect(Up46(V4Datagram(1, V4B, V4A, 250, 0, 0, IcmpFour(12, 2, new byte[] { 17, 0, 0, 0 }, inner4))).Packet is { } pointerUp2
       && pointerUp2[40] == 4 && pointerUp2[41] == 0 && pointerUp2[44] == 24,
    "§4.2's Code 2 (Bad length) takes the same pointer map, and a pointer into the IPv4 destination address lands on the IPv6 one at octet 24");
foreach (var dropped in new byte[] { 5, 6, 4, 9, 10, 13, 15, 16, 17, 18 })
    Expect(!Up46(V4Datagram(1, V4B, V4A, 250, 0, 0, IcmpFour(dropped, 0, new byte[4], eightBytes))).Ok,
        $"§4.2 silently drops ICMPv4 Type {dropped} by name");
Expect(!Up46(V4Datagram(1, V4B, V4A, 250, 0, 0, IcmpFour(99, 0, new byte[4], eightBytes))).Ok,
    "and \"Unknown ICMPv4 types: Silently drop\"");

var upTime = Up46(V4Datagram(1, V4B, V4A, 250, 0, 0, IcmpFour(11, 0, new byte[] { 0, 12, 0, 0 },
    V4Datagram(17, V4A, V4B, 7, 0, 0, UdpMessage(1, 2, new byte[20], AddressOf(V4A), AddressOf(V4B), false, 28)))));
Expect(upTime.Ok && upTime.Packet is not null && upTime.Packet[44] == 8,
    "RFC 4884 §4.2's twelve 32-bit words of quote, plus the 20 octets §4.1's header growth adds to it, is the 64-bit count §4.4 puts in the fifth octet: 68 octets is eight words");
Expect(upTime.Packet is not null && ChecksumOk(PseudoSix(AddressOf(V6B), AddressOf(V6A), 58, upTime.Packet.Length - 40),
        upTime.Packet[40..]),
    "and the checksum covers the message with the adjusted attribute inside it");

// One translation each way: the two directions have to be inverses on the octets that carry no per-family state.
var roundTrip = Up46(d!);
Expect(roundTrip.Ok && roundTrip.Packet is not null && roundTrip.Packet.AsSpan(40).SequenceEqual(udpV6),
    "IPv6 to IPv4 and back gives the original datagram, checksum included, because each direction recomputes it over its own family's pseudo-header");
Expect(roundTrip.Packet is not null && roundTrip.Packet[7] == 62,
    "and the Hop Limit is two less than the packet started with: one for each crossing (§4.1 and §5.1)");
Expect(roundTrip.Packet is not null
       && roundTrip.Packet.AsSpan(8, 16).SequenceEqual(AddressOf(V6A))
       && roundTrip.Packet.AsSpan(24, 16).SequenceEqual(AddressOf(V6B)),
    "the addresses come back through the same stateless mapping (RFC 6052 §5)");

foreach (var note in notes) Console.WriteLine($"[v6check] {note}");
if (failures.Count > 0)
{
    Console.WriteLine($"[v6check] FAIL ({failures.Count})");
    foreach (var failure in failures) Console.WriteLine($"[v6check]   {failure}");
    return 1;
}
Console.WriteLine($"[v6check] PASS - {notes.Count} IPv6 router assertions");
return 0;

internal sealed class Parsed
{
    public Parsed(byte[] datagram)
    {
        Kind = datagram[0];
        Xid = (uint)(datagram[1] << 16 | datagram[2] << 8 | datagram[3]);
        for (var i = 4; i + 4 <= datagram.Length;)
        {
            var code = BinaryPrimitives.ReadUInt16BigEndian(datagram.AsSpan(i));
            var length = BinaryPrimitives.ReadUInt16BigEndian(datagram.AsSpan(i + 2));
            if (i + 4 + length > datagram.Length) break;
            Options.Add((code, datagram.AsSpan(i + 4, length).ToArray()));
            i += 4 + length;
        }
    }

    public byte Kind { get; }
    public uint Xid { get; }
    public List<(ushort Code, byte[] Data)> Options { get; } = new();

    public byte[]? Find(ushort code)
    {
        foreach (var option in Options)
            if (option.Code == code) return option.Data;
        return null;
    }
}
