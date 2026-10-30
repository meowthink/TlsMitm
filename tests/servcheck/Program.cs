using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Router;

// Offline judgement for the router's two LAN-side services: no driver, no admin, and nothing on the
// wire but the loopback socket the listener's receive loop is handed. The pool
// is driven with hand-built client messages and the resolver with an injected transport, so every
// assertion is about bytes this program produced, not about a network it hopes to find. The inbound
// reachability probe is pinned here too - its packet, and the predicate that decides whether a datagram
// a listener received is the probe rather than a client - because that count is a verdict, and nothing
// about it can be checked against a live firewall.
const uint Server = 0xC0A80201;          // 192.168.2.1
const uint Mask = 0xFFFFFF00;            // 255.255.255.0
const uint PoolStart = 0xC0A80264;       // 192.168.2.100
const uint OutsidePool = 0xC0A802F0;     // 192.168.2.240
const uint OtherSubnet = 0xC0A80364;     // 192.168.3.100
const uint LimitedBroadcast = 0xFFFFFFFF;
const ushort TypeAaaa = 28;

var failures = new List<string>();
var notes = new List<string>();
var clock = new FakeClock();
var start = clock.Now;

void Expect(bool ok, string what)
{
    if (ok) notes.Add($"ok {what}");
    else failures.Add(what);
}

DhcpServer NewPool(int count, uint poolStart = PoolStart, uint subnetMask = Mask) => new(new DhcpConfig
{
    ServerAddress = Server,
    SubnetMask = subnetMask,
    PoolStart = poolStart,
    PoolCount = count,
    LeaseTime = TimeSpan.FromMinutes(60),
}, () => clock.Now);

// The same server with the subnets a relay agent can reach, which is what a 'giaddr' is matched against.
DhcpServer NewRelayPool(IReadOnlyList<DhcpScope> scopes) => new(new DhcpConfig
{
    ServerAddress = Server,
    SubnetMask = Mask,
    PoolStart = PoolStart,
    PoolCount = 10,
    LeaseTime = TimeSpan.FromMinutes(60),
    RelayScopes = scopes,
}, () => clock.Now);

// ------------------------------------------------------------------------------------------------
// DHCP: the DISCOVER / REQUEST round trip
// ------------------------------------------------------------------------------------------------
var pool = NewPool(10);
var macA = Mac(0x11);
var macB = Mac(0x22);
var macC = Mac(0x33);

var discover = Request(DhcpKind.Discover, macA, host: "lamp");
Expect(pool.TryReply(discover, out var offer) && offer is not null, "a DISCOVER is answered");
Expect(offer!.Kind == DhcpKind.Offer, "the answer to a DISCOVER is an OFFER");
Expect(OptionValue(ReadOptions(offer.Bytes), DhcpFormat.MessageType)![0] == 2,
    "option 53 carries the value 2 that RFC 2132 §9.6 gives to OFFER");
var offered = YiAddr(offer.Bytes);
Expect(offered == PoolStart, $"the OFFER hands out the first free pool address, got {A(offered)}");
Expect(offer.DestinationIp == LimitedBroadcast && offer.DestinationPort == DhcpPorts.ClientPort,
    "an OFFER to a client with no address goes to the limited broadcast, port 68");

var options = ReadOptions(offer.Bytes);
Expect(AddrOption(options, DhcpFormat.SubnetMask) == Mask, "option 1 is the LAN side's mask");
Expect(AddrOption(options, DhcpFormat.Router) == Server, "option 3 points the client's default route at this host");
Expect(AddrOption(options, DhcpFormat.Dns) == Server, "option 6 points the client's resolver at this host");
Expect(AddrOption(options, DhcpFormat.ServerId) == Server, "option 54 identifies this server");
Expect(AddrOption(options, DhcpFormat.Broadcast) == (Server | ~Mask), "option 28 is the subnet broadcast");
Expect(IntOption(options, DhcpFormat.LeaseTime) == 3600,
    "option 51 is the lease in seconds, which RFC 2132 §9.2 defines as a 32-bit unsigned integer");
Expect(TextOption(options, DhcpFormat.HostName) == "lamp", "the hostname from option 12 comes back in the answer");
Expect(pool.LeaseCount == 1, $"one lease exists after the OFFER, got {pool.LeaseCount}");

// Asking twice has to be the same answer: a client that retransmits its DISCOVER while the first one
// is still in the wire must not be told about a second address.
pool.TryReply(Request(DhcpKind.Discover, macA, host: "lamp"), out var repeated);
Expect(YiAddr(repeated!.Bytes) == offered, $"a retransmitted DISCOVER repeats the offer, got {A(YiAddr(repeated!.Bytes))}");

Expect(pool.TryReply(Request(DhcpKind.Request, macA, requested: offered, host: "lamp"), out var ack)
       && ack!.Kind == DhcpKind.Ack,
    "a REQUEST for the offered address is ACKed");
Expect(YiAddr(ack.Bytes) == offered, $"the ACK confirms the same address, got {A(YiAddr(ack.Bytes))}");
Expect(ack.DestinationIp == LimitedBroadcast, "an ACK to a client whose ciaddr is still empty is broadcast");

// --- renewing, the one path that unicasts --------------------------------------------------------
pool.TryReply(Request(DhcpKind.Request, macA, ciAddr: offered), out var renewed);
Expect(renewed!.Kind == DhcpKind.Ack, "a REQUEST from ciaddr with no option 50 is a renewal and is ACKed");
Expect(renewed.DestinationIp == offered && !renewed.Broadcast,
    $"a renewal with an address to receive it is unicasted, got {A(renewed.DestinationIp)}");
Expect(OptionValue(ReadOptions(renewed.Bytes), DhcpFormat.MessageType)![0] == 5,
    "option 53 carries the value 5 that RFC 2132 §9.6 gives to ACK");

pool.TryReply(Request(DhcpKind.Request, macA, ciAddr: offered, broadcastFlag: true), out var forced);
Expect(forced!.DestinationIp == LimitedBroadcast,
    "a client that set the BROADCAST flag is broadcast to even when it already has an address");

// --- the two NAKs --------------------------------------------------------------------------------
Expect(pool.TryReply(Request(DhcpKind.Request, macB, requested: OutsidePool), out var outside)
       && outside!.Kind == DhcpKind.Nak,
    "a REQUEST for an address outside the pool is NAKed rather than honoured");
Expect(OptionValue(ReadOptions(outside.Bytes), DhcpFormat.Message) is { Length: > 0 },
    "the NAK carries option 56 saying why");
Expect(pool.LeaseCount == 1, $"the NAKed request leased nothing, leases={pool.LeaseCount}");

Expect(pool.TryReply(Request(DhcpKind.Request, macB, requested: offered), out var stolen)
       && stolen!.Kind == DhcpKind.Nak,
    "a REQUEST for an address this pool holds on somebody else's lease is NAKed");

// RFC 2131 §4.1 unicasts "DHCPOFFER and DHCPACK" to ciaddr when it is set, and then separately: "In all
// cases, when 'giaddr' is zero, the server broadcasts any DHCPNAK messages to 0xffffffff". A NAK is the
// refusal of the address in ciaddr, so the client cannot be assumed to receive a unicast to it.
pool.TryReply(Request(DhcpKind.Request, macB, ciAddr: PoolStart + 5, requested: OutsidePool), out var nakToCi);
Expect(nakToCi!.Kind == DhcpKind.Nak && nakToCi.DestinationIp == LimitedBroadcast
       && nakToCi.DestinationPort == DhcpPorts.ClientPort,
    "a NAK is broadcast even when the client has an address in ciaddr");

// --- the server's own address is never leasable ---------------------------------------------------
// The two NAKs above cover "outside the pool" and "somebody else's lease". The address this host answers
// on is a third case, and option 50 reaches it whenever the pool begins below the server - the live
// configuration is exactly that shape, 192.168.0.24 serving a pool that starts at .1.
var ownPool = NewPool(50, poolStart: Server);
ownPool.TryReply(Request(DhcpKind.Discover, Mac(0x44), requested: Server), out var ownOffer);
Expect(YiAddr(ownOffer!.Bytes) != Server,
    $"a DISCOVER naming the server's own address is offered a different one, got {A(YiAddr(ownOffer.Bytes))}");
Expect(ownPool.LeaseFor(Server) is null, "no lease is recorded on the server's own address");

// Its own server, because the DISCOVER above already put somebody's lease on that address: sharing the
// pool would let the "leased to another client" NAK answer this one, and the assertion would pass
// whether or not the address-is-this-host's check exists.
var ownRequestPool = NewPool(50, poolStart: Server);
ownRequestPool.TryReply(Request(DhcpKind.Request, Mac(0x45), requested: Server), out var ownRequest);
Expect(ownRequest!.Kind == DhcpKind.Nak, $"a REQUEST for the server's own address is NAKed, got {ownRequest.Kind}");

// --- who a lease belongs to ----------------------------------------------------------------------
// RFC 2131 §4.2 makes option 61 the client's identity when it sends one, so the same NIC under a
// different identifier is a different client and must not inherit "lamp"'s address.
Expect(pool.TryReply(Request(DhcpKind.Request, macA, clientId: Id(0xAA), requested: offered), out var claimed)
       && claimed!.Kind == DhcpKind.Nak,
    "the same hardware address with a different client identifier is a different client");

pool.TryReply(Request(DhcpKind.Discover, macB, clientId: Id(0x99)), out var otherOffer);
Expect(YiAddr(otherOffer!.Bytes) == PoolStart + 1,
    $"a second client is offered the next free address, got {A(YiAddr(otherOffer.Bytes))}");
pool.TryReply(Request(DhcpKind.Request, macB, clientId: Id(0x99), requested: PoolStart + 1), out _);
Expect(pool.LeaseCount == 2, $"two clients hold two leases, got {pool.LeaseCount}");

// --- Parameter Request List ordering -------------------------------------------------------------
// RFC 2132 §9.8: a server "MUST try to insert the requested options in the order requested by the
// client", so asking for 6, 1, 3 has to come back in that order.
pool.TryReply(Request(DhcpKind.Discover, macA, prl: [DhcpFormat.Dns, DhcpFormat.SubnetMask, DhcpFormat.Router]),
    out var ordered);
var askedOrder = ReadOptions(ordered!.Bytes)
    .Select(o => o.Tag)
    .Where(t => t is DhcpFormat.Dns or DhcpFormat.SubnetMask or DhcpFormat.Router)
    .ToList();
Expect(askedOrder.SequenceEqual([DhcpFormat.Dns, DhcpFormat.SubnetMask, DhcpFormat.Router]),
    $"the requested options come back in the client's order, got {string.Join(',', askedOrder)}");
Expect(ReadOptions(ordered.Bytes).Any(o => o.Tag == DhcpFormat.LeaseTime),
    "answering a short Parameter Request List does not withhold the lease time");

// --- things that must not be answered at all -----------------------------------------------------
Expect(!pool.TryReply(Request(DhcpKind.Inform, macA, ciAddr: offered), out _),
    "a DHCPINFORM is parsed and left unanswered; the client already has its address");
Expect(!pool.TryReply(Request(DhcpKind.Discover, macA, cookie: false), out _),
    "a message without the magic cookie is BOOTP and gets no lease");
Expect(!pool.TryReply(Request(DhcpKind.Discover, macA, option53: false), out _),
    "a cookie-carrying message with no option 53 is left alone rather than leased forever");
Expect(!pool.TryReply(new byte[300], out _), "an all-zero message is not a DHCP request");
Expect(!pool.TryReply(new byte[200], out _), "a message shorter than RFC 2131 §2's 240-octet layout is refused");

// --- DECLINE reserves the address, RELEASE frees it ----------------------------------------------
var declinePool = NewPool(10);
declinePool.TryReply(Request(DhcpKind.Request, Mac(0x55), requested: PoolStart), out _);
Expect(declinePool.LeaseCount == 1, "the client that is about to decline the address holds it");
declinePool.TryReply(Request(DhcpKind.Decline, Mac(0x55), requested: PoolStart), out _);
Expect(declinePool.LeaseCount == 0, "a DECLINE drops that client's lease (RFC 2131 §4.3.3)");
declinePool.TryReply(Request(DhcpKind.Discover, Mac(0x66)), out var afterDecline);
Expect(YiAddr(afterDecline!.Bytes) == PoolStart + 1,
    $"the declined address is skipped, next offer is {A(YiAddr(afterDecline.Bytes))}");

var releasePool = NewPool(10);
releasePool.TryReply(Request(DhcpKind.Request, Mac(0x77), requested: PoolStart), out _);
releasePool.TryReply(Request(DhcpKind.Release, Mac(0x77), ciAddr: PoolStart), out _);
Expect(releasePool.LeaseCount == 0, "a RELEASE frees the lease");
releasePool.TryReply(Request(DhcpKind.Discover, Mac(0x88)), out var afterRelease);
Expect(YiAddr(afterRelease!.Bytes) == PoolStart, "a released address is in the next DISCOVER's answer");

// --- lease time, at the boundary and past it ------------------------------------------------------
var timedPool = NewPool(10);
clock.Now = start;
timedPool.TryReply(Request(DhcpKind.Request, Mac(0x99), requested: PoolStart), out _);
clock.Now = start + TimeSpan.FromMinutes(59);
timedPool.Sweep();
Expect(timedPool.LeaseCount == 1, "a lease survives inside its own 60 minutes");
clock.Now = start + TimeSpan.FromMinutes(61);
timedPool.Sweep();
Expect(timedPool.LeaseCount == 0, "the lease is gone once its 60 minutes are up");

// --- the pool is finite, and its bounds are checked ----------------------------------------------
var single = NewPool(1);
single.TryReply(Request(DhcpKind.Request, macA, requested: PoolStart), out _);
var overflowed = false;
try
{
    single.TryReply(Request(DhcpKind.Discover, macB), out _);
}
catch (InvalidOperationException)
{
    overflowed = true;
}
Expect(overflowed, "a second client on a one-address pool fails loudly instead of leasing the same address twice");

// Every candidate in ChooseAddress is tested against the served subnet, so a pool that starts outside
// it cannot hand anything out. Both outcomes are recorded rather than assumed.
var misconfigured = NewPool(4, OtherSubnet);
try
{
    misconfigured.TryReply(Request(DhcpKind.Discover, macA), out var off);
    Expect((YiAddr(off!.Bytes) & Mask) == (Server & Mask), "no address outside the LAN side's subnet is ever leased");
}
catch (InvalidOperationException)
{
    notes.Add("ok a pool entirely outside the served subnet has nothing to offer");
}

// The bounds Program.cs applies to --pool, measured against the subnet this host actually had when the
// first default was found wrong: 172.17.157.1/28, where the old network+100 start is not in the subnet
// at all. These addresses are the four octets read big-endian, so the top /24 also checks that the
// range end is compared in a space that cannot wrap.
Expect(DhcpConfig.PoolRoom(0xAC119D01, 0xFFFFFFF0) == 14, "a /28 has 14 addresses between network and broadcast");
Expect(DhcpConfig.PoolRoom(Server, Mask) == 254, "a /24 has 254");
Expect(DhcpConfig.PoolRoom(0xC0A80200, 0xFFFFFFFE) == 0, "a /31 has no address left for a pool");
Expect(DhcpConfig.PoolRoom(0xC0A80201, 0xFFFFFFFF) == -1, "a /32 reads as a refusal rather than as a count");
Expect(!DhcpConfig.PoolFitsSubnet(0xAC119D64, 50, 0xAC119D01, 0xFFFFFFF0),
    "the pool this program used to default to is refused on a /28 LAN side");
Expect(DhcpConfig.PoolFitsSubnet(0xAC119D01, 14, 0xAC119D01, 0xFFFFFFF0),
    "the mask-derived default start and count fit the same /28");
Expect(DhcpConfig.PoolFitsSubnet(PoolStart, 50, Server, Mask), "a 50-address pool inside a /24 is accepted");
Expect(!DhcpConfig.PoolFitsSubnet(OtherSubnet, 4, Server, Mask), "a pool that begins in another subnet is refused");
Expect(!DhcpConfig.PoolFitsSubnet(0xFFFFFF01, 256, 0xFFFFFF01, 0xFFFFFF00),
    "a range that runs past the broadcast address is refused even when its end wraps a uint to zero");

clock.Now = start;

// ------------------------------------------------------------------------------------------------
// DHCP through a relay agent: the scope it answers from, and where the reply is sent
// ------------------------------------------------------------------------------------------------
// 192.168.10.0/26 behind an agent at .1, deliberately a different mask from this host's own /24 so that
// every option in the answer is distinguishable from the interface defaults. A second agent, .11.1, is
// both the relay and the first-hop router of its subnet, and its address is inside its own pool.
const uint RelayMask = 0xFFFFFFC0;          // 255.255.255.192
const uint Relay = 0xC0A80A01;             // 192.168.10.1
const uint RelayNet = 0xC0A80A00;          // 192.168.10.0
const uint RelayPoolStart = 0xC0A80A02;    // 192.168.10.2
const uint Relay2 = 0xC0A80B01;            // 192.168.11.1
const uint Relay2Net = 0xC0A80B00;         // 192.168.11.0
const uint Foreign = 0xC0A80C01;           // 192.168.12.1, an agent no scope covers

var relayed = NewRelayPool([
    Scope(RelayNet, RelayMask, RelayPoolStart, 5, Relay, Server),
    Scope(Relay2Net, Mask, Relay2, 5, Relay2, Relay2),
]);
var unmatched = new List<uint>();
relayed.RelayWithoutScope += gi => unmatched.Add(gi);

Expect(relayed.TryReply(Request(DhcpKind.Discover, macA, giAddr: Relay), out var viaRelay)
       && viaRelay is not null,
    "a DISCOVER that arrived through a relay agent is answered");
var relayAddr = YiAddr(viaRelay!.Bytes);
Expect(relayAddr == RelayPoolStart, $"the OFFER comes from the relay's subnet, got {A(relayAddr)}");
Expect(viaRelay.DestinationIp == Relay && viaRelay.DestinationPort == DhcpPorts.ServerPort
       && !viaRelay.Broadcast,
    $"the reply is unicasted to the agent at {A(viaRelay.DestinationIp)} on port {viaRelay.DestinationPort} (RFC 2131 §4.1)");
Expect(viaRelay.DestinationIp != LimitedBroadcast,
    "a relayed reply is not sent to the limited broadcast, which would never leave this host's LAN side");
Expect(GiAddrOf(viaRelay.Bytes) == Relay,
    "the reply carries 'giaddr' back - RFC 1542 §4.1.2 has the agent silently discard a BOOTREPLY whose 'giaddr' is not one of its interfaces");

var relayOptions = ReadOptions(viaRelay.Bytes);
Expect(AddrOption(relayOptions, DhcpFormat.SubnetMask) == RelayMask,
    "option 1 is the scope's mask, not this host's interface mask");
Expect(AddrOption(relayOptions, DhcpFormat.Router) == Relay,
    "option 3 is the scope's router, which is the agent - this host is on the far side of it");
Expect(AddrOption(relayOptions, DhcpFormat.Dns) == Server,
    "option 6 is still this host's resolver, reached by routing rather than by the client's own link");
Expect(AddrOption(relayOptions, DhcpFormat.Broadcast) == (RelayNet | ~RelayMask),
    $"option 28 is the scope's broadcast address, got {A(AddrOption(relayOptions, DhcpFormat.Broadcast))}");
Expect(AddrOption(relayOptions, DhcpFormat.ServerId) == Server,
    "option 54 is the address the request was received on, which is what RFC 2131 §4.1 tells a server reached through a relay to use");
Expect(IntOption(relayOptions, DhcpFormat.LeaseTime) == 3600, "the lease time is the server's, not per scope");

// The same client seen from a second subnet needs a second lease: an address from the first is not
// usable where it now is (RFC 2131 §4.3.1 takes the pool from the relay agent's address).
relayed.TryReply(Request(DhcpKind.Discover, macA, giAddr: Relay2), out var secondScope);
Expect(YiAddr(secondScope!.Bytes) == Relay2 + 1,
    $"a scope whose pool begins at its router address skips it, got {A(YiAddr(secondScope.Bytes))}");
Expect(relayed.LeaseCount == 2, $"one client seen through two agents holds two leases, got {relayed.LeaseCount}");
relayed.TryReply(Request(DhcpKind.Discover, macA, giAddr: Relay), out var repeatOfRelay);
Expect(YiAddr(repeatOfRelay!.Bytes) == relayAddr,
    "and a retransmit through the first agent repeats the address leased in that scope");

// An address that is perfectly good in this host's own pool is refused for a client on the relay's
// subnet, and the refusal reaches it the same way an OFFER would.
Expect(relayed.TryReply(Request(DhcpKind.Request, macB, giAddr: Relay, requested: PoolStart), out var wrongScope)
       && wrongScope!.Kind == DhcpKind.Nak,
    "a REQUEST for an address from the wrong scope is NAKed rather than honoured");
Expect(wrongScope!.DestinationIp == Relay && wrongScope.DestinationPort == DhcpPorts.ServerPort,
    "and the NAK goes to the agent, since nothing else can deliver it to that subnet");
Expect(GiAddrOf(wrongScope.Bytes) == Relay, "the NAK carries 'giaddr' back too");

// A renewal from a client that already has an address, seen through its agent: §4.1 puts 'giaddr' first,
// so the agent is the destination even though ciaddr is set.
relayed.TryReply(Request(DhcpKind.Request, macA, ciAddr: relayAddr, giAddr: Relay), out var relayRenew);
Expect(relayRenew!.Kind == DhcpKind.Ack && relayRenew.DestinationIp == Relay
       && relayRenew.DestinationPort == DhcpPorts.ServerPort,
    "with both ciaddr and giaddr set the reply goes to the agent, not to the client's address");
Expect(YiAddr(relayRenew.Bytes) == relayAddr, "and it confirms the lease the scope holds for that client");

// The client's own broadcast preference is not this server's decision to make once an agent is in the
// path - it is the agent's, and the flag has to reach it intact.
relayed.TryReply(Request(DhcpKind.Discover, macB, giAddr: Relay, broadcastFlag: true), out var flagged);
Expect((flagged!.Bytes[10] & 0x80) != 0, "the BROADCAST flag is echoed for the agent to act on (RFC 1542 §5.4)");
Expect(flagged.DestinationIp == Relay && flagged.DestinationPort == DhcpPorts.ServerPort,
    "a client that asked to be broadcast to is still answered at the agent");

var leasesBeforeRefusal = relayed.LeaseCount;
Expect(!relayed.TryReply(Request(DhcpKind.Discover, macC, giAddr: Foreign), out var noScope) && noScope is null,
    "a relayed request whose 'giaddr' matches no scope is left unanswered");
Expect(unmatched.Count == 1 && unmatched[0] == Foreign,
    $"and the agent's address is reported to the log so the missing scope is nameable, got {A(Foreign)}");
Expect(relayed.LeaseCount == leasesBeforeRefusal,
    $"refusing an unknown scope leased nothing, leases={relayed.LeaseCount}");

// The LAN side keeps answering as before: no 'giaddr', so the interface-derived scope and port 68.
Expect(relayed.TryReply(Request(DhcpKind.Discover, macC), out var onLan) && onLan is not null,
    "a request with 'giaddr' zero is still answered");
Expect(onLan!.DestinationPort == DhcpPorts.ClientPort && onLan.DestinationIp == LimitedBroadcast
       && YiAddr(onLan.Bytes) == PoolStart,
    "and it comes from this host's own subnet and goes to the client port");

// --- the text a --scope is written in --------------------------------------------------------------
Expect(DhcpScope.TryParse("192.168.10.0/26,192.168.10.2/5,192.168.10.1", Server, out var written_, out var whyText),
    $"a well-formed --scope parses ({whyText})");
Expect(written_.Network == RelayNet && written_.SubnetMask == RelayMask,
    $"the cidr becomes the network address and mask, got {A(written_.Network)}/{A(written_.SubnetMask)}");
Expect(written_.PoolStart == RelayPoolStart && written_.PoolCount == 5, "the pool start and count come through");
Expect(written_.Router == Relay && written_.Dns == Server,
    "the router is the one written and the resolver defaults to the address the listener is bound to");
Expect(DhcpScope.TryParse("192.168.10.55/26,192.168.10.2/5,192.168.10.1", Server, out var hostBits, out _)
       && hostBits.Network == RelayNet,
    "a cidr written with host bits names the subnet it is inside, not a different one");
Expect(DhcpScope.TryParse("192.168.10.0/26,192.168.10.2/5,192.168.10.1,9.9.9.9", Server, out var withDns, out _)
       && withDns.Dns == NatTable.ParseAddress("9.9.9.9"),
    "the fourth field replaces the resolver, and it is not held to the subnet for being on the far side of the relay");
Expect(!DhcpScope.TryParse("192.168.10.0/26,192.168.10.2/70,192.168.10.1", Server, out _, out var pastBroadcast),
    $"a pool that runs past the scope's broadcast address is refused ({pastBroadcast})");
Expect(!DhcpScope.TryParse("192.168.10.0/26,192.168.11.2/5,192.168.10.1", Server, out _, out _),
    "a pool that begins in another subnet is refused");
Expect(!DhcpScope.TryParse("192.168.10.0/26,192.168.10.2/5,192.168.11.1", Server, out _, out _),
    "a router outside the scope's subnet is refused, because option 3 has to be a hop on the client's own link");
Expect(!DhcpScope.TryParse("192.168.10.0/26,192.168.10.2/5", Server, out _, out _),
    "a scope with no router is not guessed at");
Expect(!DhcpScope.TryParse("192.168.10.0,192.168.10.2/5,192.168.10.1", Server, out _, out _),
    "a cidr with no prefix length is refused");
Expect(!DhcpScope.TryParse("192.168.10.0/33,192.168.10.2/5,192.168.10.1", Server, out _, out _),
    "a prefix length past 32 is refused");
Expect(!DhcpScope.TryParse("192.168.10.0/26,192.168.10.2/0,192.168.10.1", Server, out _, out _),
    "a pool of no addresses is refused");
Expect(!DhcpScope.TryParse("192.168.10.0/26,ten/5,192.168.10.1", Server, out _, out _),
    "an address that is not dotted-quad is refused rather than thrown past");
Expect(NatTable.MaskFromPrefix(24) == Mask && NatTable.MaskFromPrefix(0) == 0
       && NatTable.MaskFromPrefix(32) == 0xFFFFFFFF,
    "a prefix length becomes the four octets read big-endian, and /0 the mask that matches everything");

// ------------------------------------------------------------------------------------------------
// DNS: parsing, forwarding, caching, truncation, local names
// ------------------------------------------------------------------------------------------------

var leasedPool = NewPool(10);
leasedPool.TryReply(Request(DhcpKind.Request, macA, requested: PoolStart, host: "Printer"), out _);

var upstreamCalls = new List<(byte[] Message, bool Tcp)>();
var canned = new Queue<byte[]>();
byte[]? Transport(byte[] message, bool useTcp)
{
    upstreamCalls.Add((message, useTcp));
    return canned.Count > 0 ? canned.Dequeue() : null;
}
var queries = new List<(string Name, ushort Type, uint Client)>();
var dns = new DnsServer(Transport, name => leasedPool.AddressOfHostName(name), () => clock.Now);
dns.Queried += (name, type, client) => queries.Add((name, type, client));

// --- what a stub resolver must refuse ------------------------------------------------------------
Expect(!dns.TryRespond(Response("qr.example.com", DnsFormat.TypeA, []), Server, out _),
    "a message with the QR bit set is an answer, not a question to be answered");
Expect(!dns.TryRespond(RawQuery("example.com", DnsFormat.TypeA, questions: 2), Server, out _),
    "a header claiming more than one question is refused rather than half-parsed");
Expect(!dns.TryRespond(RawQuery("example.com", DnsFormat.TypeA, flags: 0x1100), Server, out _),
    "an opcode other than QUERY (RFC 1035 §4.1.1) is left alone");
Expect(!dns.TryRespond(RawQuery("example.com", DnsFormat.TypeA, labelLengthViolation: true), Server, out _),
    "a label longer than the 63 octets RFC 1035 §3.1 allows is refused");
Expect(!dns.TryRespond(RawQuery("example.com", DnsFormat.TypeA, compressedQuestionName: true), Server, out _),
    "a compression pointer in a question name is refused rather than resolved");
Expect(!dns.TryRespond(RawQuery("example.com", DnsFormat.TypeA, cls: 255), Server, out _),
    "a query class other than IN is not this server's to answer");

// --- forwarding, and whose transaction id the reply carries ---------------------------------------
// The client asks with 0xABCD and this server puts its own id on the upstream query, so the answer
// coming back has to be re-labelled before it reaches the client.
upstreamCalls.Clear();
canned.Enqueue(Response("www.example.com", DnsFormat.TypeA, [(60, 0xC0A86401)], id: 0x0001));
Expect(dns.TryRespond(RawQuery("www.example.com", DnsFormat.TypeA, id: 0xABCD), Server, out var forward)
       && forward is not null,
    "an unknown name is looked up upstream");
Expect(BinaryPrimitives.ReadUInt16BigEndian(forward!.AsSpan(0, 2)) == 0xABCD,
    $"the reply carries the client's id, got {BinaryPrimitives.ReadUInt16BigEndian(forward.AsSpan(0, 2)):X4}");
Expect(upstreamCalls.Count == 1
       && BinaryPrimitives.ReadUInt16BigEndian(upstreamCalls[0].Message.AsSpan(0, 2)) != 0xABCD,
    "the upstream query is sent under a different id, so a stale answer cannot be matched to the wrong client");
Expect(!upstreamCalls[0].Tcp, "the first attempt is UDP, which is what RFC 1035 §4.2.1 carries a message on");

// --- the cache, held by the TTL -------------------------------------------------------------------
upstreamCalls.Clear();
Expect(dns.TryRespond(RawQuery("www.example.com", DnsFormat.TypeA, id: 0x0002), Server, out var cachedReply)
       && upstreamCalls.Count == 0,
    "a second query inside the record's TTL is answered with no upstream traffic");
Expect(!ReferenceEquals(forward, cachedReply), "the cached message is copied, not handed out in place");
Expect(BinaryPrimitives.ReadUInt16BigEndian(cachedReply!.AsSpan(0, 2)) == 0x0002,
    "the cached bytes are re-labelled with this client's id");
Expect(dns.CacheCount == 1, $"one name is cached, got {dns.CacheCount}");

clock.Now = start + TimeSpan.FromSeconds(59);
Expect(dns.TryRespond(RawQuery("www.example.com", DnsFormat.TypeA, id: 0x0003), Server, out _)
       && upstreamCalls.Count == 0,
    "the cache still answers at 59s of a 60s TTL (RFC 1035 §3.2.1: the interval the record may be cached for)");
clock.Now = start + TimeSpan.FromSeconds(61);
dns.Sweep();
Expect(!dns.TryRespond(RawQuery("www.example.com", DnsFormat.TypeA, id: 0x0004), Server, out _)
       && upstreamCalls.Count == 1,
    "at 61s of a 60s TTL the name is asked upstream again");
Expect(dns.CacheCount == 0, "the entry past its TTL is reaped by Sweep rather than kept as a miss");

upstreamCalls.Clear();
canned.Enqueue(Response("www.example.com", TypeAaaa, [(60, 0xC0A86401)]));
dns.TryRespond(RawQuery("www.example.com", TypeAaaa), Server, out _);
Expect(upstreamCalls.Count == 1, "a cached A record is not served in answer to a query for another type");

// --- what never gets stored -----------------------------------------------------------------------
upstreamCalls.Clear();
canned.Enqueue(Response("nothing.example.com", DnsFormat.TypeA, []));
Expect(dns.TryRespond(RawQuery("nothing.example.com", DnsFormat.TypeA), Server, out var empty)
       && !DnsFormat.HasAnswers(empty!),
    "an upstream answer with no records is passed straight through");
dns.TryRespond(RawQuery("nothing.example.com", DnsFormat.TypeA), Server, out _);
Expect(upstreamCalls.Count == 2,
    "a NOERROR without answers is not cached: negative caching is RFC 2308, which this server does not implement");

upstreamCalls.Clear();
var storedBefore = dns.CacheCount;
canned.Enqueue(Response("zero.example.com", DnsFormat.TypeA, [(0, 0xC0A86402)]));
dns.TryRespond(RawQuery("zero.example.com", DnsFormat.TypeA), Server, out _);
Expect(dns.CacheCount == storedBefore, "an answer whose shortest TTL is 0 is not stored at all");
dns.TryRespond(RawQuery("zero.example.com", DnsFormat.TypeA), Server, out _);
Expect(upstreamCalls.Count == 2, "and the next query for that name goes upstream again");

upstreamCalls.Clear();
Expect(!dns.TryRespond(RawQuery("down.example.com", DnsFormat.TypeA), Server, out var dead) && dead is null,
    "when the upstream gives nothing, no reply is invented and none is sent");

// --- one stalled question is not every client's stall ---------------------------------------------
// The same object answers the UDP and the TCP listener, and the upstream exchange sits outside the
// cache's lock: a question the resolver leaves hanging costs its own client the wait and nobody else.
// Measured on this host, the resolver stalls SVCB/HTTPS questions for some names but answers A at once,
// which is the shape that made the LAN look like it had no DNS while this host itself was fine.
var slowEntered = new ManualResetEventSlim(false);
var releaseSlow = new ManualResetEventSlim(false);
var sharedDns = new DnsServer((message, useTcp) =>
{
    if (!DnsFormat.TryReadQuery(message, out var sent)) return null;
    if (sent.Question.Name == "stalled.example.com")
    {
        slowEntered.Set();
        releaseSlow.Wait(TimeSpan.FromSeconds(10));
    }
    return Response(sent.Question.Name, sent.Question.Type, [(60, 0xC0A86405)], id: sent.Id);
}, _ => null, () => clock.Now);

byte[]? stalledReply = null;
var stalled = Task.Run(() =>
    sharedDns.TryRespond(RawQuery("stalled.example.com", DnsFormat.TypeA, id: 0x2001), Server, out stalledReply));
Expect(slowEntered.Wait(TimeSpan.FromSeconds(2)),
    "the stalled question reaches the upstream transport, which is what the next one has to outrun");

byte[]? quickReply = null;
var quick = Task.Run(() =>
    sharedDns.TryRespond(RawQuery("quick.example.com", DnsFormat.TypeA, id: 0x2002), Server, out quickReply));
Expect(quick.Wait(TimeSpan.FromSeconds(2)) && quick.Result,
    "a second client's question is answered while the first is still waiting upstream");
Expect(quickReply is not null && BinaryPrimitives.ReadUInt16BigEndian(quickReply.AsSpan(0, 2)) == 0x2002,
    "and the answer that came back mid-stall is that second client's own");

releaseSlow.Set();
Expect(stalled.Wait(TimeSpan.FromSeconds(10)) && stalled.Result,
    "the stalled question is answered once upstream answers");
Expect(stalledReply is not null && BinaryPrimitives.ReadUInt16BigEndian(stalledReply.AsSpan(0, 2)) == 0x2001,
    "the stalled client's answer carries its own id, not the one that overtook it");

// --- and the receive loop is not where the stall comes back ----------------------------------------
// One level up: two datagrams arrive on the listener's one socket, and the second has to be answered
// while the first is inside the transport. Awaiting each answer before reading the next datagram is
// exactly what a client sees as "the LAN has no DNS". A loopback socket is the only socket here, and it
// needs neither admin nor a driver.
var listenEntered = new ManualResetEventSlim(false);
var listenRelease = new ManualResetEventSlim(false);
var listeningDns = new DnsServer((message, useTcp) =>
{
    if (!DnsFormat.TryReadQuery(message, out var sent)) return null;
    if (sent.Question.Name == "stalled.example.com")
    {
        listenEntered.Set();
        listenRelease.Wait(TimeSpan.FromSeconds(10));
    }
    return Response(sent.Question.Name, sent.Question.Type, [(60, 0xC0A86406)], id: sent.Id);
}, _ => null, () => clock.Now);

var listener = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
var listenPort = ((IPEndPoint)listener.Client.LocalEndPoint!).Port;
// A probe whose source is not the loopback client's, so nothing this test sends can be taken for it.
var serving = Services.RunDns(listener, listeningDns, 0,
    new LanProbe("servcheck", (ushort)listenPort, 0x7F000002, 0xFFFF), CancellationToken.None);

using var clientA = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
using var clientB = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
var resolver = new IPEndPoint(IPAddress.Loopback, listenPort);
clientA.Send(RawQuery("stalled.example.com", DnsFormat.TypeA, id: 0x3001), resolver);
Expect(listenEntered.Wait(TimeSpan.FromSeconds(2)),
    "the first datagram is inside the transport, holding it there");

clientB.Send(RawQuery("quick.example.com", DnsFormat.TypeA, id: 0x3002), resolver);
byte[]? answeredQuick = null;
clientB.Client.ReceiveTimeout = 2000;
try
{
    var from = new IPEndPoint(IPAddress.Any, 0);
    answeredQuick = clientB.Receive(ref from);
}
catch (SocketException)
{
    // Left null, which the assertion below reports: a serialised listener answers only after the first.
}
Expect(answeredQuick is not null && BinaryPrimitives.ReadUInt16BigEndian(answeredQuick.AsSpan(0, 2)) == 0x3002,
    "the second datagram is answered while the first is still inside the transport");

listenRelease.Set();
byte[]? answeredSlow = null;
clientA.Client.ReceiveTimeout = 5000;
try
{
    var from = new IPEndPoint(IPAddress.Any, 0);
    answeredSlow = clientA.Receive(ref from);
}
catch (SocketException)
{
}
Expect(answeredSlow is not null && BinaryPrimitives.ReadUInt16BigEndian(answeredSlow.AsSpan(0, 2)) == 0x3001,
    "and the held datagram is answered once the transport does");

listener.Dispose();
Expect(serving.Wait(TimeSpan.FromSeconds(2)), "the receive loop ends when its socket is closed");


// --- truncation means ask the same question over TCP ----------------------------------------------
// RFC 1035 §4.2.1 restricts a UDP message and sets TC when it had to cut one; §4.2.2 is the TCP path,
// where a two-octet length stands in for the 512-octet ceiling.
upstreamCalls.Clear();
canned.Enqueue(Response("big.example.com", DnsFormat.TypeA, [(60, 0xC0A86403)], truncated: true));
canned.Enqueue(Response("big.example.com", DnsFormat.TypeA, [(60, 0xC0A86403), (60, 0xC0A86404)]));
Expect(dns.TryRespond(RawQuery("big.example.com", DnsFormat.TypeA), Server, out var whole) && whole is not null,
    "a truncated UDP answer is retried");
Expect(upstreamCalls.Count == 2 && upstreamCalls[1].Tcp, "the retry is the same question over TCP");
Expect(DnsFormat.HasAnswers(whole!) && BinaryPrimitives.ReadUInt16BigEndian(whole.AsSpan(6, 2)) == 2,
    $"the client gets the untruncated answer, records={BinaryPrimitives.ReadUInt16BigEndian(whole.AsSpan(6, 2))}");
Expect(!DnsFormat.IsTruncated(whole!), "the TC bit from the UDP attempt is not forwarded to the client");

// --- an answer over the ceiling UDP allows ----------------------------------------------------------
// RFC 1035 §4.2.1: "Messages carried by UDP are restricted to 512 bytes (not counting the header and UDP
// trailer)... Longer messages are truncated and the TC bit is set in the header." The cut has to leave a
// message the client can still parse, so it lands between whole records and the header's counts follow.
upstreamCalls.Clear();
var fortyRecords = Many(40);
Expect(DnsFormat.TryReadSections(fortyRecords, out var askedEnd, out var walked) && walked.Count == 40,
    $"a 40-record answer walks to its 40 records, got {walked.Count}");
Expect(fortyRecords.Length > DnsFormat.UdpMessageLimit,
    $"the message is {fortyRecords.Length} octets, past the {DnsFormat.UdpMessageLimit} UDP allows");
canned.Enqueue(fortyRecords);
Expect(dns.TryRespond(RawQuery("huge.example.com", DnsFormat.TypeA), Server, out var huge) && huge is not null,
    "the resolver takes the whole answer from upstream");
Expect(huge!.Length == fortyRecords.Length && !DnsFormat.IsTruncated(huge),
    "and what it holds is the upstream message with the id rewritten, not a cut one: cutting before the cache would lose records for every client after");
var cut = DnsFormat.TruncateForUdp(huge)!;
Expect(cut.Length <= DnsFormat.UdpMessageLimit, $"the UDP copy fits, got {cut.Length} octets");
Expect(DnsFormat.IsTruncated(cut), "and it carries TC, which is the signal that sends the client to TCP");
Expect(DnsFormat.TryReadSections(cut, out var cutQuestionEnd, out var kept)
       && BinaryPrimitives.ReadUInt16BigEndian(cut.AsSpan(6, 2)) == (ushort)kept.Count,
    "the answer count is the number of records physically still there");
Expect(kept.Count > 0 && kept.Count < 40, $"the cut dropped records rather than inventing one, kept={kept.Count}");
Expect(cutQuestionEnd == askedEnd, "the question is still whole: only records go");
Expect(fortyRecords.AsSpan(askedEnd, cut.Length - cutQuestionEnd)
       .SequenceEqual(cut.AsSpan(cutQuestionEnd, cut.Length - cutQuestionEnd)),
    "and what survived is the beginning of the answer, byte for byte, not a scatter of it");
Expect(DnsFormat.TruncateForUdp(whole!).SequenceEqual(whole!),
    "a message already inside the ceiling comes back as it was, TC and all");

// All three sections use §3.2.1's one record shape, so a message built with its records in the answer
// section is re-labelled as a three-section one rather than re-encoded.
var mixed = SplitSections(Many(38), 36, 1, 1);
Expect(DnsFormat.TryReadSections(mixed, out _, out var mixedRecords)
       && mixedRecords.Count == 38 && mixedRecords[36].Section == DnsSection.Authority
       && mixedRecords[37].Section == DnsSection.Additional,
    "the walk puts each record in the section its count said it belonged to");
var cutMixed = DnsFormat.TruncateForUdp(mixed)!;
Expect(DnsFormat.TryReadSections(cutMixed, out _, out var keptMixed)
       && BinaryPrimitives.ReadUInt16BigEndian(cutMixed.AsSpan(6, 2)) == (ushort)keptMixed.Count
       && BinaryPrimitives.ReadUInt16BigEndian(cutMixed.AsSpan(8, 2)) == (ushort)keptMixed.Count(s => s.Section == DnsSection.Authority)
       && BinaryPrimitives.ReadUInt16BigEndian(cutMixed.AsSpan(10, 2)) == (ushort)keptMixed.Count(s => s.Section == DnsSection.Additional),
    "and every section's count is rewritten to its own records, so nothing is promised that the bytes do not carry");
Expect(BinaryPrimitives.ReadUInt16BigEndian(cutMixed.AsSpan(10, 2)) == 0 && keptMixed.Count(s => s.Section == DnsSection.Answer) > 0,
    "the sections at the end go first, which is why the answer itself is what reaches the client");

// A record whose RDLENGTH runs past the end cannot be placed, so the walk stops where it got to. In the
// 16-octet record this fixture builds, RDLENGTH is the sixth and seventh bytes from the end: the four
// address octets of RDATA follow it.
var overrun = Many(3).ToArray();
BinaryPrimitives.WriteUInt16BigEndian(overrun.AsSpan(overrun.Length - 6, 2), 400);
Expect(DnsFormat.TryReadSections(overrun, out _, out var halfWalked) && halfWalked.Count == 2,
    $"an overrun record is not counted, got {halfWalked.Count}");

// One step earlier in the same record: a message that stops inside the fixed part leaves a name that reads
// but no TYPE after it. The header still claims every record, so the walk's own list is the only answer to
// how much of this message a caller can name.
var midRecord = fortyRecords.AsSpan(0, askedEnd + 16 * 2 + 5).ToArray();
Expect(DnsFormat.TryReadSections(midRecord, out _, out var twoWhole) && twoWhole.Count == 2
       && twoWhole[1].Section == DnsSection.Answer
       && BinaryPrimitives.ReadUInt16BigEndian(midRecord.AsSpan(6, 2)) == 40,
    $"a message ending inside a record's fixed part still walks the {twoWhole.Count} whole records before that cut");

// Bytes that belong to no record are not part of the message either: §4.1.1's counts say what follows the
// question, and this fixture claims nothing follows it.
var noRecords = Response("wide.example.com", DnsFormat.TypeA, []);
var withFiller = new byte[noRecords.Length + 600];
noRecords.CopyTo(withFiller, 0);
var fillerCut = DnsFormat.TruncateForUdp(withFiller);
Expect(fillerCut is not null && fillerCut.Length == noRecords.Length
       && DnsFormat.IsTruncated(fillerCut) && !DnsFormat.HasAnswers(fillerCut),
    $"a message longer than the ceiling with no records in it is cut back to its question, got {fillerCut?.Length} of {withFiller.Length} octets");

// A question is the one part a response cannot lose: §4.1.1 puts it first and the records after it. The
// name here is past the 255 octets §3.1 allows, which is how this server's own walker is coaxed into a
// question section longer than the ceiling.
Expect(DnsFormat.TruncateForUdp(WideQuestion(9)) is null,
    "an answer whose question is itself past the ceiling is refused rather than cut into something no client can match back to its query");

// --- the same answer, over the leg §4.2.2 gives it --------------------------------------------------
upstreamCalls.Clear();
var tcpOut = new MemoryStream();
Services.ServeDnsConnection(new MemoryStream(Prefixed(RawQuery("huge.example.com", DnsFormat.TypeA, id: 0x3344))),
    tcpOut, dns, 0xC0A80210);
var tcpReply = tcpOut.ToArray();
Expect(upstreamCalls.Count == 0, "the whole answer the cache holds goes out on this leg too, with no second query upstream");
Expect(tcpReply.Length == fortyRecords.Length + 2
       && BinaryPrimitives.ReadUInt16BigEndian(tcpReply.AsSpan(0, 2)) == (ushort)fortyRecords.Length,
    $"the two-octet length of RFC 1035 §4.2.2 is in front of the message, got {tcpReply.Length} octets");
Expect(tcpReply.AsSpan(4).SequenceEqual(fortyRecords.AsSpan(2))
       && !DnsFormat.IsTruncated(tcpReply.AsSpan(2)),
    "all 40 records arrive on the leg with no 512 ceiling, past the prefix and the id, and TC is not set on it");
Expect(BinaryPrimitives.ReadUInt16BigEndian(tcpReply.AsSpan(2, 2)) == 0x3344,
    "and the transaction id is the one this client asked with");

var silentOut = new MemoryStream();
Services.ServeDnsConnection(new MemoryStream(), silentOut, dns, 0xC0A80210);
Expect(silentOut.Length == 0, "a connection that sends nothing is answered with nothing, and the loop moves on");
var zeroOut = new MemoryStream();
Services.ServeDnsConnection(new MemoryStream([0, 0]), zeroOut, dns, 0xC0A80210);
Expect(zeroOut.Length == 0, "a length prefix of zero is not a message");
var halfOut = new MemoryStream();
Services.ServeDnsConnection(new MemoryStream([0, 40, 1, 2, 3]), halfOut, dns, 0xC0A80210);
Expect(halfOut.Length == 0, "a connection that stops partway through its query is left unanswered");

// --- names this pool handed out --------------------------------------------------------------------
upstreamCalls.Clear();
Expect(dns.TryRespond(RawQuery("printer.lan", DnsFormat.TypeA), 0xC0A80210, out var local) && local is not null,
    "a leased hostname is answered from the pool");
Expect(upstreamCalls.Count == 0, "a local name never leaves the host");
Expect(BinaryPrimitives.ReadUInt16BigEndian(local!.AsSpan(4, 2)) == 1
       && BinaryPrimitives.ReadUInt16BigEndian(local.AsSpan(6, 2)) == 1,
    "the local answer has one question and one record");
Expect((BinaryPrimitives.ReadUInt16BigEndian(local.AsSpan(2, 2)) & 0x0400) != 0,
    "the answer is marked authoritative, which is the AA bit RFC 1035 §4.1.1 gives a server that is authoritative for the name");
Expect(BinaryPrimitives.ReadUInt16BigEndian(local.AsSpan(local.Length - 6, 2)) == 4,
    "an A record's RDLENGTH is 4, for the 32-bit Internet address of RFC 1035 §3.4.1");
Expect(BinaryPrimitives.ReadUInt32BigEndian(local.AsSpan(local.Length - 4, 4)) == PoolStart,
    $"the local answer is the leased address, got {A(BinaryPrimitives.ReadUInt32BigEndian(local.AsSpan(local.Length - 4, 4)))}");
Expect(BinaryPrimitives.ReadUInt32BigEndian(local.AsSpan(local.Length - 10, 4)) == DnsServer.LocalAnswerTtl,
    $"a local answer's TTL is the short fixed one, got {BinaryPrimitives.ReadUInt32BigEndian(local.AsSpan(local.Length - 10, 4))}");
Expect(local.Length <= DnsFormat.UdpMessageLimit, "a locally built answer fits inside the UDP message limit");
Expect(queries.Any(q => q.Name == "printer.lan" && q.Client == 0xC0A80210),
    "the querying client is reported to the log, which is the identity a remote device has in place of a PID");

upstreamCalls.Clear();
dns.TryRespond(RawQuery("PRINTER.LAN", DnsFormat.TypeA), Server, out _);
Expect(upstreamCalls.Count == 0, "a leased name is matched without regard to case");

upstreamCalls.Clear();
canned.Enqueue(Response("printer.lan", TypeAaaa, []));
dns.TryRespond(RawQuery("printer.lan", TypeAaaa), Server, out _);
Expect(upstreamCalls.Count == 1, "a leased name asked for a type other than A still goes upstream");

Expect(leasedPool.AddressOfHostName("lamp") is null, "a hostname never leased to anybody resolves to nothing");

// --- reading a record's TTL through a compression pointer -------------------------------------------
// The stored response cannot outlive the shortest TTL among its records (RFC 1035 §3.2.1), so the walk
// has to clear a CNAME whose RDATA is a pointer back into the message (§4.1.4) and land on the next.
var chain = new (ushort Type, uint Ttl, byte[] RData)[]
{
    (5, 120, [0xC0, 0x0C]),
    (DnsFormat.TypeA, 30, DnsFormat.AddressBytes(0xC0A86405)),
};
Expect(DnsFormat.ShortestAnswerTtl(Message("chain.example.com", DnsFormat.TypeA, chain)) == 30,
    $"the shortest TTL is read past a CNAME whose RDATA is a pointer, got {DnsFormat.ShortestAnswerTtl(Message("chain.example.com", DnsFormat.TypeA, chain))}");
Expect(DnsFormat.ShortestAnswerTtl(Response("x.example.com", DnsFormat.TypeA, [(300, 0xC0A86406)])) == 300,
    "a single A record reports its own TTL");
Expect(DnsFormat.ShortestAnswerTtl(Response("x.example.com", DnsFormat.TypeA, [])) is null,
    "a response with no answers has no TTL to honour");

// --- the ECH configuration a client must not receive -----------------------------------------------
// RFC 9848 §3 is how the configuration reaches a client: the HTTPS record's "ech" SvcParamKey (value 5
// in the RFC's IANA table) "conveys the ECH configuration". The rewrite keeps every length where it was
// and changes only the key, so the record still parses and the client has nothing to encrypt with -
// RFC 9460 §2.4.3 has it ignore a key it does not know, and §14.3.2 makes 65280-65534 private use.
var echConfig = Encoding.ASCII.GetBytes("AEX+DQBBAAA=");        // base64 of an ECHConfigList, §3
byte[] EchKeyPattern() => [0x00, 0x05, (byte)(echConfig.Length >> 8), (byte)echConfig.Length];
var echRdata = HttpsRdata(1, ".", (1, Encoding.ASCII.GetBytes("h2")), (DnsFormat.SvcParamEch, echConfig));

var echMessage = Message("ech.example.com", DnsFormat.TypeHttps, [(DnsFormat.TypeHttps, 60, echRdata)]);
var echBefore = echMessage.ToArray();
Expect(DnsFormat.NeutralizeEch(echMessage) == 1, "the one ech parameter of an HTTPS record is rewritten");
Expect(echMessage.Length == echBefore.Length,
    "the message keeps its length, which is what lets the same rewrite happen inside a packet");
var changed = Enumerable.Range(0, echBefore.Length).Where(i => echBefore[i] != echMessage[i]).ToArray();
Expect(changed.Length == 2
       && BinaryPrimitives.ReadUInt16BigEndian(echMessage.AsSpan(changed[0], 2)) == DnsFormat.SvcParamPrivateUse,
    $"exactly the two SvcParamKey octets change, and to the private-use key, got {changed.Length} octets");
Expect(Contains(echMessage, [0x00, 0x01, 0x00, 0x02, (byte)'h', (byte)'2']),
    "the alpn parameter beside it is untouched");
Expect(DnsFormat.NeutralizeEch(echMessage) == 0, "a second pass finds nothing left to rewrite");

var plainHttps = Message("plain.example.com", DnsFormat.TypeHttps,
    [(DnsFormat.TypeHttps, 60, HttpsRdata(1, ".", (1, Encoding.ASCII.GetBytes("h2"))))]);
var plainBefore = plainHttps.ToArray();
Expect(DnsFormat.NeutralizeEch(plainHttps) == 0 && plainHttps.SequenceEqual(plainBefore),
    "an HTTPS record with no ech parameter is left exactly as it arrived");

var svcbAlias = Message("alias.example.com", DnsFormat.TypeSvcb,
    [(DnsFormat.TypeSvcb, 60, HttpsRdata(0, "target.example.net", (1, Encoding.ASCII.GetBytes("h3")),
        (DnsFormat.SvcParamEch, echConfig)))]);
Expect(DnsFormat.NeutralizeEch(svcbAlias) == 1,
    "an SVCB alias carries the parameter the same way and is rewritten too");

var brokenRdata = new List<byte> { 0x00, 0x01, 0x00 };           // priority 1, root target name
brokenRdata.AddRange(Short(DnsFormat.SvcParamEch));
brokenRdata.AddRange(Short(0xFF));                               // a length its value does not have
var broken = Message("broken.example.com", DnsFormat.TypeHttps, [(DnsFormat.TypeHttps, 60, brokenRdata.ToArray())]);
try
{
    Expect(DnsFormat.NeutralizeEch(broken) == 0,
        "a parameter whose length runs past its RDATA is not rewritten");
}
catch (Exception ex)
{
    Expect(false, $"a malformed parameter must not throw, but {ex.GetType().Name} came out");
}

upstreamCalls.Clear();
canned.Enqueue(Message("ech.example.com", DnsFormat.TypeHttps, [(DnsFormat.TypeHttps, 60, echRdata)]));
Expect(dns.TryRespond(RawQuery("ech.example.com", DnsFormat.TypeHttps), Server, out var servedEch)
       && servedEch is not null,
    "the resolver answers an HTTPS question");
Expect(!Contains(servedEch!, EchKeyPattern()),
    "the answer it serves carries no ech parameter, so the client is handed no configuration");
Expect(Contains(servedEch!, [0xFF, 0x00, 0x00, (byte)echConfig.Length]),
    "the parameter is still there under the private-use key instead, which the client ignores");
upstreamCalls.Clear();
dns.TryRespond(RawQuery("ech.example.com", DnsFormat.TypeHttps), Server, out var cachedEch);
Expect(upstreamCalls.Count == 0 && cachedEch is not null && !Contains(cachedEch, EchKeyPattern()),
    "the cached copy is the neutralised one, so a cache hit cannot hand the configuration back");

// --- the same rewrite, on an answer that never reaches that resolver --------------------------------
// The host's own resolver answer is local delivery, so Router's reply leg is the only place it can be
// read. What the helper answers to is the bytes: IPv4, a whole datagram, and a source port of 53.
const uint HostAddress = 0xC0A8017D;                              // 192.168.1.125, the WAN side
byte[] FreshEch() => Message("host.example.com", DnsFormat.TypeHttps,
    [(DnsFormat.TypeHttps, 60, HttpsRdata(1, ".", (DnsFormat.SvcParamEch, echConfig)))]);

var udpAnswer = UdpDatagram(0xC0A80101, DnsPorts.ServerPort, HostAddress, 55555, FreshEch());
var udpBefore = udpAnswer.ToArray();
Expect(DnsEch.TryNeutralize(udpAnswer) == 1,
    "a UDP answer from the resolver's port is rewritten inside the datagram");
Expect(udpAnswer.Length == udpBefore.Length && !Contains(udpAnswer, EchKeyPattern()),
    "it keeps its length and carries no ech key, so the caller only has to redo the checksums");

Expect(DnsEch.TryNeutralize(UdpDatagram(0xC0A80101, 80, HostAddress, 55555, FreshEch())) == 0,
    "a datagram that is not from the resolver's port is not looked into");
Expect(DnsEch.TryNeutralize(UdpDatagram(HostAddress, 55555, 0xC0A80101, DnsPorts.ServerPort, FreshEch())) == 0,
    "a query on its way out has no records to rewrite");

var fragmented = UdpDatagram(0xC0A80101, DnsPorts.ServerPort, HostAddress, 55555, FreshEch());
BinaryPrimitives.WriteUInt16BigEndian(fragmented.AsSpan(6, 2), 0x2000);   // RFC 791 §3.2, MF set
Expect(DnsEch.TryNeutralize(fragmented) == 0,
    "a fragmented datagram is left alone: the message it carries is not all in it");

var tcpAnswer = TcpSegment(0xC0A80101, DnsPorts.ServerPort, HostAddress, 55556, Prefixed(FreshEch()));
Expect(DnsEch.TryNeutralize(tcpAnswer) == 1,
    "a TCP segment carrying the whole message behind §4.2.2's length is rewritten too");
Expect(!Contains(tcpAnswer, EchKeyPattern()), "and it is the same rewrite, inside the segment's payload");

var tcpPartial = TcpSegment(0xC0A80101, DnsPorts.ServerPort, HostAddress, 55556,
    Prefixed(FreshEch()).AsSpan(0, 10).ToArray());
Expect(DnsEch.TryNeutralize(tcpPartial) == 0,
    "a segment holding only part of the message is left alone rather than half-read");

var v6 = UdpDatagram(0xC0A80101, DnsPorts.ServerPort, HostAddress, 55555, FreshEch());
v6[0] = 0x60;
Expect(DnsEch.TryNeutralize(v6) == 0, "only IPv4 is parsed here, the version nibble deciding first");

// --- the inbound probe, and what must not be mistaken for it ---------------------------------------
// The listener's own arrival count is the reachability verdict, so the predicate that decides "this is my
// probe" is the thing that can lie. Two directions matter: a client's real message must never count as a
// probe, and the probe must never reach the server behind it, because an unanswered DISCOVER would still
// have reserved a lease.
const uint ProbeSource = 0xC0A802FE;         // 192.168.2.254, one below this /24's last address
const ushort ProbeToken = 0x4A7B;
var probe = new LanProbe("dhcp", DhcpPorts.ServerPort, ProbeSource, ProbeToken);
var otherProbe = new LanProbe("dns", DnsPorts.ServerPort, ProbeSource, 0x9E37);

Expect(LanProbe.ProbeSource(Server, Mask) == ProbeSource,
    $"/24 probe source is {A(LanProbe.ProbeSource(Server, Mask))}");
Expect(LanProbe.ProbeSource(0xAC100504, 0xFFFF0000) == 0xAC10FFFE,
    $"/16 probe source is {A(LanProbe.ProbeSource(0xAC100504, 0xFFFF0000))}, not one below this host's own address");
foreach (var (address, subnet) in new[] { (Server, Mask), (0xAC100504u, 0xFFFF0000u) })
{
    var source = LanProbe.ProbeSource(address, subnet);
    Expect((source & subnet) == (address & subnet), $"{A(source)} is inside the subnet {A(address)} serves");
    Expect(source != address && source != (address | ~subnet),
        $"{A(source)} is neither this host's own {A(address)} nor the all-ones {A(address | ~subnet)}");
}

var datagram = probe.Build(Server, DhcpPorts.ClientPort);
Expect(datagram.Length == 38, $"the probe is an IPv4 and UDP header around a {LanProbe.Marker.Length + 2}-octet payload, got {datagram.Length}");
Expect(datagram[0] == 0x45, $"IPv4 with a 20-octet header, got {datagram[0]:X2}");
Expect(BinaryPrimitives.ReadUInt16BigEndian(datagram.AsSpan(2)) == datagram.Length,
    $"total length says the packet's own length, got {BinaryPrimitives.ReadUInt16BigEndian(datagram.AsSpan(2))}");
Expect(datagram[9] == 17, $"protocol is UDP, got {datagram[9]}");
Expect(BinaryPrimitives.ReadUInt32BigEndian(datagram.AsSpan(12)) == ProbeSource,
    $"source is the probe's own address, got {A(BinaryPrimitives.ReadUInt32BigEndian(datagram.AsSpan(12)))}");
Expect(BinaryPrimitives.ReadUInt32BigEndian(datagram.AsSpan(16)) == Server,
    $"destination is the address the listener is bound to, got {A(BinaryPrimitives.ReadUInt32BigEndian(datagram.AsSpan(16)))}");
Expect(BinaryPrimitives.ReadUInt16BigEndian(datagram.AsSpan(20)) == DhcpPorts.ClientPort,
    $"source port is a DHCP client's 68, got {BinaryPrimitives.ReadUInt16BigEndian(datagram.AsSpan(20))}");
Expect(BinaryPrimitives.ReadUInt16BigEndian(datagram.AsSpan(22)) == DhcpPorts.ServerPort,
    $"destination port is the one this probe was made for, got {BinaryPrimitives.ReadUInt16BigEndian(datagram.AsSpan(22))}");
Expect(BinaryPrimitives.ReadUInt16BigEndian(datagram.AsSpan(24)) == datagram.Length - 20,
    "RFC 768's length member counts the UDP header and its data, not the IPv4 header above them, got " +
    BinaryPrimitives.ReadUInt16BigEndian(datagram.AsSpan(24)));
Expect(BinaryPrimitives.ReadUInt16BigEndian(datagram.AsSpan(26)) == 0,
    "the checksum is left for the driver to fill, got " + BinaryPrimitives.ReadUInt16BigEndian(datagram.AsSpan(26)).ToString("X4"));
Expect(datagram.AsSpan(28, LanProbe.Marker.Length).SequenceEqual(LanProbe.Marker), "the payload opens with the marker");
Expect(BinaryPrimitives.ReadUInt16BigEndian(datagram.AsSpan(28 + LanProbe.Marker.Length)) == ProbeToken,
    $"and carries the token, got {BinaryPrimitives.ReadUInt16BigEndian(datagram.AsSpan(28 + LanProbe.Marker.Length)):X4}");

var payload = datagram[28..];
Expect(probe.Consume(payload, ProbeSource), "the listener's own probe is taken");
Expect(probe.Arrivals == 1, $"and counted once, got {probe.Arrivals}");
Expect(!probe.Consume(payload, Server), "the same bytes from this host's own address are not the probe: that would be a local client");
Expect(!probe.Consume(payload, 0), "and not from 0.0.0.0 either, which is where a client with no address sends from");
Expect(!probe.Consume(otherProbe.Build(Server, LanProbe.EphemeralSourcePort)[28..], ProbeSource),
    "another probe's token does not count for this one");
Expect(!probe.Consume(payload[..^2], ProbeSource), "a truncated payload is not a probe");
Expect(!probe.Consume([.. payload, .. "extra"u8], ProbeSource), "nor is a longer one");
Expect(!probe.Consume(Request(DhcpKind.Discover, macA), ProbeSource), "a client's real DISCOVER is not a probe");
Expect(!probe.Consume(RawQuery("example.com", DnsFormat.TypeA), ProbeSource), "a client's real query is not a probe");
Expect(probe.Arrivals == 1, $"and none of those moved the count, which is at {probe.Arrivals}");
Expect(otherProbe.Arrivals == 0, "a port's answer is never paid for by another port's probe");

// Even taken by nobody, the payload has to be nothing to the servers behind it: a probe that reserved a
// lease or answered itself a name would be a side effect the run reports as a client.
Expect(!pool.TryReply(payload, out _), "the lease server refuses the probe's payload outright");
Expect(!dns.TryRespond(payload, ProbeSource, out _), "and the resolver does too");
Expect(payload[0] != 1 && payload[0] != 2,
    "the payload's first octet is neither BOOTREQUEST nor BOOTREPLY, so it cannot be read as a DHCP message");

foreach (var note in notes) Console.WriteLine($"[servcheck] {note}");

if (failures.Count > 0)
{
    Console.WriteLine($"[servcheck] FAIL ({failures.Count})");
    foreach (var failure in failures) Console.WriteLine($"[servcheck]   {failure}");
    return 1;
}
Console.WriteLine($"[servcheck] PASS - {notes.Count} DHCP, DNS and inbound-probe assertions");
return 0;

static string A(uint address) => NatTable.FormatAddress(address);

static byte[] Mac(byte last) => [0x02, 0x00, 0x00, 0x00, 0x00, last];

// RFC 2131 §4.2's client identifier for an Ethernet address is the hardware type followed by the
// address, which is why the two are one option value rather than the MAC on its own.
static byte[] Id(byte last) => [0x01, 0x02, 0x00, 0x00, 0x00, 0x00, last];

// A scope is what a relay agent's subnet needs to be answered from: a mask, a pool, and the two
// addresses the client is pointed at.
static DhcpScope Scope(uint network, uint mask, uint poolStart, int count, uint router, uint dns) => new()
{
    Network = network,
    SubnetMask = mask,
    PoolStart = poolStart,
    PoolCount = count,
    Router = router,
    Dns = dns,
};

// A message this program sends as a client, laid out per RFC 2131 §2 Figure 1: flags at 10, ciaddr at
// 12, chaddr at 28, the magic cookie at 236. 'giaddr' at 24 is what a relay agent fills in, so asking for
// it here is how a request that came through one is reproduced.
static byte[] Request(DhcpKind kind, byte[] mac, uint ciAddr = 0, uint requested = 0, byte[]? clientId = null,
    string? host = null, bool broadcastFlag = false, byte[]? prl = null, bool cookie = true, bool option53 = true,
    uint giAddr = 0)
{
    var header = new byte[DhcpFormat.HeaderLength];
    header[0] = 1; // BOOTREQUEST, the only kind that arrives at a server
    header[1] = 1; // Ethernet
    header[2] = (byte)mac.Length;
    BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4, 4), 0x12345678);
    if (broadcastFlag) header[10] = 0x80;
    BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(12, 4), ciAddr);
    BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(24, 4), giAddr);
    mac.CopyTo(header.AsSpan(28));
    if (cookie) BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(236, 4), DhcpFormat.MagicCookie);

    var options = new List<byte>();
    if (option53) AddOption(options, 53, [(byte)kind]);
    if (requested != 0) AddOption(options, 50, DhcpFormat.Address(requested));
    if (clientId is not null) AddOption(options, 61, clientId);
    if (host is not null) AddOption(options, 12, Encoding.ASCII.GetBytes(host));
    if (prl is not null) AddOption(options, 55, prl);
    options.Add(255);

    var message = new byte[header.Length + options.Count];
    header.CopyTo(message, 0);
    options.CopyTo(message, header.Length);
    return message;
}

static void AddOption(List<byte> options, byte tag, byte[] value)
{
    options.Add(tag);
    options.Add((byte)value.Length);
    options.AddRange(value);
}

static List<(byte Tag, byte[] Value)> ReadOptions(byte[] message)
{
    var found = new List<(byte, byte[])>();
    for (var i = DhcpFormat.HeaderLength; i + 2 <= message.Length;)
    {
        var tag = message[i];
        if (tag == DhcpFormat.End) break;
        if (tag == DhcpFormat.Pad) { i++; continue; }
        var length = message[i + 1];
        if (i + 2 + length > message.Length) break;
        found.Add((tag, message.AsSpan(i + 2, length).ToArray()));
        i += 2 + length;
    }
    return found;
}

static byte[]? OptionValue(List<(byte Tag, byte[] Value)> options, byte tag)
    => options.FirstOrDefault(o => o.Tag == tag).Value;

static uint AddrOption(List<(byte Tag, byte[] Value)> options, byte tag)
{
    var value = OptionValue(options, tag);
    return value is { Length: 4 } ? BinaryPrimitives.ReadUInt32BigEndian(value) : 0;
}

static int IntOption(List<(byte Tag, byte[] Value)> options, byte tag)
{
    var value = OptionValue(options, tag);
    return value is { Length: 4 } ? (int)BinaryPrimitives.ReadUInt32BigEndian(value) : -1;
}

static string? TextOption(List<(byte Tag, byte[] Value)> options, byte tag)
{
    var value = OptionValue(options, tag);
    return value is { Length: > 0 } ? Encoding.ASCII.GetString(value) : null;
}

static uint YiAddr(byte[] message) => BinaryPrimitives.ReadUInt32BigEndian(message.AsSpan(16, 4));

// BOOTP offset 24, the field a relay agent has to find its own address in to be able to deliver the reply.
static uint GiAddrOf(byte[] message) => BinaryPrimitives.ReadUInt32BigEndian(message.AsSpan(24, 4));

// A query as a client sends it: the header of RFC 1035 §4.1.1, then the name as length-prefixed labels
// followed by QTYPE and QCLASS (§4.1.2).
static byte[] RawQuery(string name, ushort type, ushort cls = DnsFormat.ClassInternet, ushort id = 0x1111,
    ushort flags = 0x0100, int questions = 1, bool labelLengthViolation = false, bool compressedQuestionName = false)
{
    var body = new List<byte>();
    if (compressedQuestionName)
    {
        body.AddRange([0xC0, 0x0C]);
    }
    else
    {
        foreach (var label in Labels(name, labelLengthViolation))
        {
            body.Add((byte)label.Length);
            body.AddRange(label);
        }
        body.Add(0);
    }
    body.AddRange(Short(type));
    body.AddRange(Short(cls));
    return WithHeader(body, id, flags, (ushort)questions, 0);
}

// A resolver's answer: the question echoed, then each record with its NAME written as the pointer to
// offset 12 that RFC 1035 §4.1.4 describes.
static byte[] Response(string name, ushort type, (uint Ttl, uint Addr)[] answers, ushort id = 0, bool truncated = false)
    => Message(name, type, answers
        .Select(a => ((ushort)DnsFormat.TypeA, a.Ttl, DnsFormat.AddressBytes(a.Addr)))
        .ToArray(), id, truncated);

// An answer of `count` A records for `name`, each one the 16 octets a pointer name, §3.2.1's ten-octet
// fixed part and a 4-octet address come to. The addresses differ so which records survived a cut is
// readable off the bytes.
static byte[] Many(int count, string name = "huge.example.com")
    => Response(name, DnsFormat.TypeA,
        Enumerable.Range(0, count).Select(i => ((uint)60, (uint)(0xC0A80201 + i * 3))).ToArray());

// A question of `labels` labels of the longest legal name, for the message whose question alone is past
// the UDP ceiling.
static byte[] WideQuestion(int labels)
    => Many(2, string.Join('.', Enumerable.Repeat(new string('x', 63), labels)));

// RFC 1035 §4.2.2's framing: the message with its own length in front of it.
static byte[] Prefixed(byte[] message)
{
    var framed = new byte[message.Length + 2];
    BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)message.Length);
    message.CopyTo(framed.AsSpan(2));
    return framed;
}

// RFC 9460 §2.2: the priority, the TargetName written out in full rather than as a pointer, then each
// SvcParam as its key and length in front of its value.
static byte[] HttpsRdata(ushort priority, string target, params (ushort Key, byte[] Value)[] parameters)
{
    var rdata = new List<byte>(Short(priority));
    foreach (var label in Labels(target, false))
    {
        rdata.Add((byte)label.Length);
        rdata.AddRange(label);
    }
    rdata.Add(0);
    foreach (var (key, value) in parameters)
    {
        rdata.AddRange(Short(key));
        rdata.AddRange(Short((ushort)value.Length));
        rdata.AddRange(value);
    }
    return rdata.ToArray();
}

// An IPv4 datagram around a payload, the header of RFC 791 §3.1. The checksums are left at zero: this is
// about where the message sits, and nothing under test verifies them.
static byte[] UdpDatagram(uint source, ushort sourcePort, uint destination, ushort destinationPort, byte[] payload)
{
    var datagram = new byte[20 + 8 + payload.Length];
    datagram[0] = 0x45;
    BinaryPrimitives.WriteUInt16BigEndian(datagram.AsSpan(2, 2), (ushort)datagram.Length);
    datagram[8] = 64;
    datagram[9] = 17;
    BinaryPrimitives.WriteUInt32BigEndian(datagram.AsSpan(12, 4), source);
    BinaryPrimitives.WriteUInt32BigEndian(datagram.AsSpan(16, 4), destination);
    BinaryPrimitives.WriteUInt16BigEndian(datagram.AsSpan(20, 2), sourcePort);
    BinaryPrimitives.WriteUInt16BigEndian(datagram.AsSpan(22, 2), destinationPort);
    BinaryPrimitives.WriteUInt16BigEndian(datagram.AsSpan(24, 2), (ushort)(8 + payload.Length));
    payload.CopyTo(datagram.AsSpan(28));
    return datagram;
}

// An IPv4 segment around a payload, with the 20-octet TCP header whose data offset is at octet 12.
static byte[] TcpSegment(uint source, ushort sourcePort, uint destination, ushort destinationPort, byte[] payload)
{
    var segment = new byte[20 + 20 + payload.Length];
    segment[0] = 0x45;
    BinaryPrimitives.WriteUInt16BigEndian(segment.AsSpan(2, 2), (ushort)segment.Length);
    segment[8] = 64;
    segment[9] = 6;
    BinaryPrimitives.WriteUInt32BigEndian(segment.AsSpan(12, 4), source);
    BinaryPrimitives.WriteUInt32BigEndian(segment.AsSpan(16, 4), destination);
    BinaryPrimitives.WriteUInt16BigEndian(segment.AsSpan(20, 2), sourcePort);
    BinaryPrimitives.WriteUInt16BigEndian(segment.AsSpan(22, 2), destinationPort);
    segment[32] = 0x50;                 // 5 words of header, nothing optional behind it
    segment[33] = 0x10;                 // ACK
    BinaryPrimitives.WriteUInt16BigEndian(segment.AsSpan(34, 2), 65535);
    payload.CopyTo(segment.AsSpan(40));
    return segment;
}

static bool Contains(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
{
    for (var i = 0; i + needle.Length <= haystack.Length; i++)
        if (haystack.Slice(i, needle.Length).SequenceEqual(needle)) return true;
    return false;
}

// The three counts of a message whose record bytes were built as one answer section. Every section uses
// §3.2.1's common record shape, so re-labelling a fixture is not re-encoding it.
static byte[] SplitSections(byte[] message, ushort answers, ushort authorities, ushort additionals)
{
    var copy = message.ToArray();
    BinaryPrimitives.WriteUInt16BigEndian(copy.AsSpan(6, 2), answers);
    BinaryPrimitives.WriteUInt16BigEndian(copy.AsSpan(8, 2), authorities);
    BinaryPrimitives.WriteUInt16BigEndian(copy.AsSpan(10, 2), additionals);
    return copy;
}

static byte[] Message(string name, ushort type, (ushort Type, uint Ttl, byte[] RData)[] records,
    ushort id = 0, bool truncated = false)
{
    var body = new List<byte>();
    foreach (var label in Labels(name, false))
    {
        body.Add((byte)label.Length);
        body.AddRange(label);
    }
    body.Add(0);
    body.AddRange(Short(type));
    body.AddRange(Short(DnsFormat.ClassInternet));

    foreach (var record in records)
    {
        body.AddRange([0xC0, 0x0C]);
        body.AddRange(Short(record.Type));
        body.AddRange(Short(DnsFormat.ClassInternet));
        var ttl = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(ttl, record.Ttl);
        body.AddRange(ttl);
        body.AddRange(Short((ushort)record.RData.Length));
        body.AddRange(record.RData);
    }

    var flags = (ushort)(0x8000 | 0x0400 | 0x0080);
    if (truncated) flags |= 0x0200;
    return WithHeader(body, id, flags, 1, (ushort)records.Length);
}

static byte[] WithHeader(List<byte> body, ushort id, ushort flags, ushort questions, ushort answers)
{
    var message = new byte[DnsFormat.HeaderLength + body.Count];
    BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(0, 2), id);
    BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(2, 2), flags);
    BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(4, 2), questions);
    BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(6, 2), answers);
    body.CopyTo(message, DnsFormat.HeaderLength);
    return message;
}

static IEnumerable<byte[]> Labels(string name, bool tooLong)
{
    foreach (var label in name.Split('.', StringSplitOptions.RemoveEmptyEntries))
    {
        var bytes = Encoding.ASCII.GetBytes(label);
        if (tooLong) bytes = new byte[64];
        yield return bytes;
    }
}

static byte[] Short(ushort value)
{
    var bytes = new byte[2];
    BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
    return bytes;
}

internal sealed class FakeClock
{
    public DateTime Now { get; set; } = new(2026, 10, 27, 12, 0, 0, DateTimeKind.Utc);
}
