using System.Buffers.Binary;
using Router;

// Offline judgement for the router's NAT: no driver, no admin, no sockets. Each case builds one
// packet, hands it to NatTable, and asserts what came out of the rewrite.
const int LanIfIdx = 12;
const int WanIfIdx = 7;
const int OtherIfIdx = 99;

// Translate is given the egress the host's routing decision picked and the WAN index it was configured
// with; the pair to compare is those two, not LAN against WAN. There is no ingress to pass: the forward
// layer is downstream of the routing decision and its address names only the egress.

var failures = new List<string>();
var notes = new List<string>();

var wan = NatTable.ParseAddress("203.0.113.9");
var lanAddr = NatTable.ParseAddress("192.0.2.1");
var lanMask = NatTable.ParseAddress("255.255.255.0");
var client = NatTable.ParseAddress("192.0.2.50");
var lanPeer = NatTable.ParseAddress("192.0.2.77");
var server = NatTable.ParseAddress("198.51.100.7");
var server2 = NatTable.ParseAddress("198.51.100.8");
var broadcast = 0xFFFFFFFFu;

var clock = new FakeClock();
var table = new NatTable(wan, lanAddr, lanMask, () => clock.Now);
var start = clock.Now;

// --- TCP forward, and the mapping has to be endpoint-independent -------------------------------
var syn = Frame(6, client, server, Tcp(4000, 443, 0x02));
var snat = table.Translate(syn.AsSpan(), WanIfIdx, WanIfIdx);
Expect(snat.Action == NatAction.Snat, "a LAN client's SYN is source-NATed");
Expect(Src(syn) == wan, $"the source becomes the WAN address, got {A(Src(syn))}");
Expect(Dst(syn) == server && Dport(syn) == 443, "the destination is left untouched");
var natPort = Sport(syn);
Expect(natPort is >= 49152 and <= 65535, $"the mapped port comes from the dynamic range, got {natPort}");
Expect(table.FlowCount == 1, $"one flow exists, got {table.FlowCount}");

// The tripwire for RFC 4787 REQ-1: a NAT MUST map endpoint-independently, so the same client socket
// talking to a second server has to come out on the same mapped port.
var syn2 = Frame(6, client, server2, Tcp(4000, 443, 0x02));
table.Translate(syn2.AsSpan(), WanIfIdx, WanIfIdx);
Expect(Sport(syn2) == natPort, $"the same client socket maps to the same port for a different server, got {Sport(syn2)} vs {natPort}");
Expect(table.FlowCount == 1, $"a second server adds no second flow, got {table.FlowCount}");

// --- TCP reverse, from the WAN ---------------------------------------------------------------------
var reply = Frame(6, server, wan, Tcp(443, natPort, 0x12));
var dnat = table.Translate(reply.AsSpan(), WanIfIdx, WanIfIdx);
Expect(dnat.Action == NatAction.Dnat, "the server's reply is destination-NATed back to the client");
Expect(Dst(reply) == client && Dport(reply) == 4000, $"the destination becomes the client's socket, got {A(Dst(reply))}:{Dport(reply)}");
Expect(Src(reply) == server && Sport(reply) == 443, "the source stays the server, so the client's own socket still matches");

// The reply matched on the mapped port alone, so nothing in front of it can be an interface condition.
// Handing the same packet an egress index that is not the WAN is how that stays stated rather than
// assumed: a route that returns the answer through a different interface is legal (RFC 4787 REQ-1
// makes the mapping endpoint-independent, so the port is the whole key).
var proxyReply = Frame(6, server, wan, Tcp(443, natPort, 0x18));
var localDnat = table.Translate(proxyReply.AsSpan(), OtherIfIdx, WanIfIdx);
Expect(localDnat.Action == NatAction.Dnat && Dst(proxyReply) == client,
    "the same reply is translated on an egress interface that is not the WAN");

var bogus = Frame(6, server, wan, Tcp(443, (ushort)(natPort + 1), 0x12));
Expect(table.Translate(bogus.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.None,
    "an unmapped port on the WAN address is not translated into somebody's session");

// --trace asks this to keep following a packet after the rewrite has replaced the client's address with
// the WAN one: from then on neither address and neither interface belongs to the LAN, so the mapped port
// is the only thing that still identifies the flow.
Expect(table.IsMappedPort(6, natPort), "the port this table handed out is recognised as mapped");
Expect(!table.IsMappedPort(6, (ushort)(natPort + 1)), "its neighbour is not, so an unmapped packet is not traced as somebody's flow");
Expect(!table.IsMappedPort(17, natPort), "and the mapping is per protocol, so a UDP packet on that number is not traced as this TCP flow");

// --- what must stay out of the NAT --------------------------------------------------------------
var own = Frame(6, wan, server, Tcp(51000, 443, 0x02));
Expect(table.Translate(own.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.None,
    "a source that is this host's WAN address is not a LAN client, so it is not source-NATed");

var sideways = Frame(6, client, lanPeer, Tcp(4001, 445, 0x02));
Expect(table.Translate(sideways.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.None,
    "LAN to LAN is not forwarded");

var toRouter = Frame(17, client, lanAddr, Udp(68, 67));
Expect(table.Translate(toRouter.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.None,
    "a packet to this interface's own address is left for the local listener");

var discover = Frame(17, client, broadcast, Udp(68, 67));
Expect(table.Translate(discover.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.None,
    "a DHCPDISCOVER to 255.255.255.255 is not rewritten out the WAN");

var wrongIfBefore = table.WrongIf;
var wrongIf = Frame(6, client, server, Tcp(4002, 443, 0x02));
Expect(table.Translate(wrongIf.AsSpan(), LanIfIdx, WanIfIdx).Action == NatAction.None,
    "a client packet whose egress is the LAN interface is not rewritten here");
Expect(table.WrongIf == wrongIfBefore + 1,
    $"but it is counted: a wrong --wan leaves every other path working, so the counter is the only thing that says so, got {table.WrongIf} vs {wrongIfBefore}");

Expect(table.Translate(Frame(6, wan, server, Tcp(51001, 443, 0x02)).AsSpan(), OtherIfIdx, WanIfIdx).Action == NatAction.None
       && table.WrongIf == wrongIfBefore + 1,
    "a source outside the LAN on an egress of its own does not move that counter");

Expect(table.Translate(Frame(6, client, lanPeer, Tcp(4004, 445, 0x02)).AsSpan(), OtherIfIdx, WanIfIdx).Action == NatAction.None
       && table.WrongIf == wrongIfBefore + 1,
    "nor does a LAN-to-LAN packet, which was never a forwarding candidate");

var fragBefore = table.Fragments;
var frag = Frame(6, client, server, Tcp(4003, 443, 0x02), fragmentOffset: 100);
Expect(table.Translate(frag.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.None
       && table.Fragments == fragBefore + 1,
    "a fragment past the first of a datagram this table has not translated is passed through and counted, not half-translated");

var protoBefore = table.UnmappedProtocol;
var gre = Frame(47, client, server, new byte[8]);
Expect(table.Translate(gre.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.None
       && table.UnmappedProtocol == protoBefore + 1,
    "a protocol with no port concept is passed through and counted");

var icmpError = Frame(1, client, server, Icmp(3, 0x4321));
Expect(table.Translate(icmpError.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.Discard,
    "an ICMP error is not mapped as if it were a query, and one that quotes nothing is dropped for that");

// --- UDP and ICMP round trips -------------------------------------------------------------------
var query = Frame(17, client, server, Udp(5353, 53));
Expect(table.Translate(query.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.Snat, "a UDP query is source-NATed");
var udpPort = Sport(query);
var answer = Frame(17, server, wan, Udp(53, udpPort));
Expect(table.Translate(answer.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.Dnat
       && Dst(answer) == client && Dport(answer) == 5353,
    "the UDP answer reaches the client's own socket");

var echo = Frame(1, client, server, Icmp(8, 0x1234));
Expect(table.Translate(echo.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.Snat, "an ICMP echo request is mapped on its identifier");
var echoId = IcmpId(echo);
Expect(echoId != 0x1234, $"the identifier is rewritten, got {echoId}");
var echoReply = Frame(1, server, wan, Icmp(0, echoId));
Expect(table.Translate(echoReply.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.Dnat
       && Dst(echoReply) == client && IcmpId(echoReply) == 0x1234,
    "the echo reply is unmapped back to the client's identifier");

// --- the mapped port keeps the internal port's parity --------------------------------------------
// RFC 4787 REQ-4: "It is RECOMMENDED that a NAT have a 'Port parity preservation' behavior of 'Yes'."
// A fresh table because the slot arithmetic below is judged from the start of the range; on a table
// that has already allocated, the parity assertion holds but these exact numbers do not.
clock.Now = start;
var parityTable = new NatTable(wan, lanAddr, lanMask, () => clock.Now);

var rtp = Frame(17, client, server, Udp(5004, 5005));
parityTable.Translate(rtp.AsSpan(), WanIfIdx, WanIfIdx);
var rtpNat = Sport(rtp);
Expect(rtpNat % 2 == 0, $"an even internal port maps to an even port, got {rtpNat}");
Expect(rtpNat is >= 49152 and <= 65535, $"the mapped port stays in the dynamic range, got {rtpNat}");

var rtcp = Frame(17, client, server, Udp(5005, 5006));
parityTable.Translate(rtcp.AsSpan(), WanIfIdx, WanIfIdx);
var rtcpNat = Sport(rtcp);
Expect(rtcpNat % 2 == 1, $"an odd internal port maps to an odd port, got {rtcpNat}");
Expect(rtcpNat == rtpNat + 1, $"the pair allocated back to back stays adjacent, got {rtpNat} and {rtcpNat}");

var otherRtp = Frame(17, lanPeer, server, Udp(5004, 5005));
parityTable.Translate(otherRtp.AsSpan(), WanIfIdx, WanIfIdx);
var otherNat = Sport(otherRtp);
Expect(otherNat % 2 == 0 && otherNat != rtpNat,
    $"a second client on the same even port still gets an even mapped port, got {otherNat} vs {rtpNat}");

var oddAlone = Frame(17, NatTable.ParseAddress("192.0.2.88"), server, Udp(7001, 5005));
parityTable.Translate(oddAlone.AsSpan(), WanIfIdx, WanIfIdx);
Expect(Sport(oddAlone) % 2 == 1, $"a third client whose internal port is odd is not forced onto an even one, got {Sport(oddAlone)}");

// --- expiry, at the RFC floors and not before ---------------------------------------------------
// One table per protocol: on a shared table an unrelated shorter-lived mapping would expire inside
// another case's window, and the assertion would no longer say what it claims to.
clock.Now = start;

// RFC 4787 REQ-5 forbids a UDP timer under two minutes and recommends a default of five minutes or
// more, so the default has to clear both numbers, and a configured longer one has to be honoured.
var udpTable = new NatTable(wan, lanAddr, lanMask, () => clock.Now);
var udpFlow = Frame(17, client, server, Udp(6000, 53));
udpTable.Translate(udpFlow.AsSpan(), WanIfIdx, WanIfIdx);
var udpNatPort = Sport(udpFlow);
clock.Now = start + TimeSpan.FromSeconds(119);
udpTable.Sweep();
Expect(udpTable.FlowCount == 1, "a UDP mapping survives 119s, below the two-minute floor of RFC 4787 REQ-5");
clock.Now = start + TimeSpan.FromSeconds(299);
udpTable.Sweep();
Expect(udpTable.FlowCount == 1, "the default UDP timer is not the floor: it survives 299s");
clock.Now = start + TimeSpan.FromSeconds(301);
udpTable.Sweep();
Expect(udpTable.FlowCount == 0, "and it is the recommended five minutes, gone at 301s");

var lateAnswer = Frame(17, server, wan, Udp(53, udpNatPort));
Expect(udpTable.Translate(lateAnswer.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.None,
    "an answer arriving after the mapping expired is not delivered to the client");

clock.Now = start;
var longUdp = new NatTable(wan, lanAddr, lanMask, () => clock.Now, TimeSpan.FromMinutes(10));
var longFlow = Frame(17, client, server, Udp(6001, 53));
longUdp.Translate(longFlow.AsSpan(), WanIfIdx, WanIfIdx);
clock.Now = start + TimeSpan.FromSeconds(599);
longUdp.Sweep();
Expect(longUdp.FlowCount == 1, "--udp-timeout 600 keeps the mapping long after the default's five minutes");
clock.Now = start + TimeSpan.FromSeconds(605);
longUdp.Sweep();
Expect(longUdp.FlowCount == 0, "and still expires on the configured ten minutes");

var refused = false;
try
{
    _ = new NatTable(wan, lanAddr, lanMask, () => clock.Now, TimeSpan.FromSeconds(119));
}
catch (ArgumentOutOfRangeException)
{
    refused = true;
}
Expect(refused, "a UDP timer below the RFC 4787 REQ-5 floor is refused, not silently rounded up");

clock.Now = start;

clock.Now = start;
var tcpTable = new NatTable(wan, lanAddr, lanMask, () => clock.Now);
var fin = Frame(6, client, server, Tcp(4000, 443, 0x01));
tcpTable.Translate(fin.AsSpan(), WanIfIdx, WanIfIdx);
clock.Now = start + TimeSpan.FromMinutes(3);
tcpTable.Sweep();
Expect(tcpTable.FlowCount == 1, "a TCP mapping that saw a FIN survives 3 minutes (RFC 5382 REQ-5 transitory floor is four)");
clock.Now = start + TimeSpan.FromMinutes(5);
tcpTable.Sweep();
Expect(tcpTable.FlowCount == 0, "the transitory TCP mapping is gone at 5 minutes");

clock.Now = start;
var established = Frame(6, client, server2, Tcp(4100, 443, 0x10));
tcpTable.Translate(established.AsSpan(), WanIfIdx, WanIfIdx);
clock.Now = start + TimeSpan.FromHours(2);
tcpTable.Sweep();
Expect(tcpTable.FlowCount == 1, "an established TCP mapping survives two hours (RFC 5382 REQ-5 floor is 2h4m)");
clock.Now = start + TimeSpan.FromMinutes(125);
tcpTable.Sweep();
Expect(tcpTable.FlowCount == 0, "the established TCP mapping is gone at 2h5m");

clock.Now = start;
var icmpTable = new NatTable(wan, lanAddr, lanMask, () => clock.Now);
var ping = Frame(1, client, server, Icmp(8, 0x77));
icmpTable.Translate(ping.AsSpan(), WanIfIdx, WanIfIdx);
clock.Now = start + TimeSpan.FromSeconds(59);
icmpTable.Sweep();
Expect(icmpTable.FlowCount == 1, "an ICMP query mapping survives 59s (RFC 5508 REQ-2 floor is 60s)");
clock.Now = start + TimeSpan.FromSeconds(61);
icmpTable.Sweep();
Expect(icmpTable.FlowCount == 0, "the ICMP query mapping is gone at 61s");

// --- an ICMP error quotes the packet it complains about, in its rewritten form -------------------
// RFC 5508 REQ-4/REQ-5: the quote has to be reverted with the same mapping and the outer header pointed
// at the host the reverted quote names, or the path MTU it carries matches no socket anywhere. The
// product's own one's-complement loop is not trusted here: Csum below is RFC 1071's 32-bit accumulation
// form, an independent algorithm, so a quote that validates here really validates.
clock.Now = start;
var errTable = new NatTable(wan, lanAddr, lanMask, () => clock.Now);

var errFlow = Frame(17, client, server, Udp(4002, 4003));
errTable.Translate(errFlow.AsSpan(), WanIfIdx, WanIfIdx);
var errNatPort = Sport(errFlow);
var payload = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD };
// The quote is the original datagram's internet header and its first 64 bits (RFC 791 §3.1), and the
// UDP checksum inside it was computed over the pseudo-header the WAN rewrite left behind.
var quotedHeader = Udp(errNatPort, 4003);
WriteUdpLength(quotedHeader, (ushort)(8 + payload.Length));
WriteUdpChecksum(quotedHeader, UdpChecksum(wan, server, quotedHeader, payload));
var bigMtu = Frame(1, server, wan, Error(3, 4, Quote(17, wan, server, quotedHeader)));
var errBefore = errTable.IcmpErrors;
var bigMtuOutcome = errTable.Translate(bigMtu.AsSpan(), WanIfIdx, WanIfIdx);
Expect(bigMtuOutcome.Action == NatAction.IcmpError,
    $"an unreachable-from-the-WAN error about a flow of ours is translated, got {bigMtuOutcome.Action} {(bigMtuOutcome.Reason ?? "")}");
Expect(errTable.IcmpErrors == errBefore + 1, "and it is counted as its own action, not as a DNAT");
Expect(Dst(bigMtu) == client, $"the outer destination becomes the client the quote now names, got {A(Dst(bigMtu))}");
Expect(Src(bigMtu) == server, "the outer source stays the router that sent the notice, so the client sees who spoke");
Expect(bigMtu[20] == 3 && bigMtu[21] == 4, "and the type and code are left alone, as REQ-4b requires");
Expect(QSrc(bigMtu) == client && QSport(bigMtu) == 4002,
    $"the quote's source is back to the client's own tuple, got {A(QSrc(bigMtu))}:{QSport(bigMtu)}");
Expect(QDst(bigMtu) == server && QDport(bigMtu) == 4003, "the quote's destination was never rewritten, so it stays");
Expect(Csum(QuotedHeader(bigMtu)) == 0, "the quote's own internet header still adds up after its address changed");
Expect(QChecksum(bigMtu) == UdpChecksum(client, server, QuotedTransport(bigMtu), payload),
    "the quoted UDP checksum was folded to the value a fresh computation over the client's tuple gives");

// The two drop reasons have to be tellable apart on a live run, because both look like a client that
// simply never learned the path MTU.
var errDropsBefore = errTable.IcmpErrorsDropped;
var unmapped = Frame(1, server, wan, Error(3, 4, Quote(17, wan, server, Udp((ushort)(errNatPort + 7), 4003))));
Expect(errTable.Translate(unmapped.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.Discard
       && errTable.IcmpErrorsDropped == errDropsBefore + 1,
    "an error whose quote matches no flow of ours is dropped, not forwarded with a private address in it");
Expect(Dst(unmapped) == wan, "and it is dropped as it arrived, with nothing rewritten");
Expect(errTable.Translate(unmapped.AsSpan(), WanIfIdx, WanIfIdx).Reason!.Contains("no flow owns"),
    "the reason names the lookup that failed");

var corrupt = Frame(1, server, wan, Error(3, 4, Quote(17, wan, server, quotedHeader)));
corrupt[38] ^= 0xFF;   // the quoted header's own checksum field, at 20 + 8 + 10
Expect(errTable.Translate(corrupt.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.Discard
       && errTable.Translate(corrupt.AsSpan(), WanIfIdx, WanIfIdx).Reason!.Contains("does not validate"),
    "REQ-3a: a quote that does not validate is dropped for that reason, not for want of a mapping");

// REQ-3b: the quoted transport header is behind any options in the quoted packet, not at a fixed 20.
var withOptions = Frame(1, server, wan,
    Error(11, 0, Quote(17, wan, server, quotedHeader, options: new byte[] { 0x82, 0x04, 0, 0 })));
Expect(errTable.Translate(withOptions.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.IcmpError
       && QSrc(withOptions) == client && QSport(withOptions) == 4002,
    "a quoted header with an IP option is read past the option, and the revert lands in the right words");

// RFC 4884 §4.1: the four octets before the quote are a length over the quoted packet, so a non-zero
// value says extensions follow it. The quote itself does not move, and that is what this pins.
var withExtensions = Frame(1, server, wan, Error(3, 4, Quote(17, wan, server, quotedHeader), unused: 2));
Expect(errTable.Translate(withExtensions.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.IcmpError,
    "a non-zero RFC 4884 length is not read as a reason to stop looking for the quote");

// REQ-5: an error the client raised about a packet it received. The quote names the client, so the flow
// is found by the client's own tuple and the quote goes out to the public form; REQ-5c has the outer
// source become this host's own address, which is also the only source that can leave.
var clientSide = Frame(1, client, server, Error(3, 1, Quote(17, server, client, Udp(4003, 4002))));
Expect(errTable.Translate(clientSide.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.IcmpError
       && Src(clientSide) == wan,
    $"an error from the client leaves looking like it came from this host, got {A(Src(clientSide))}");
Expect(Dst(clientSide) == server && QDst(clientSide) == wan && QDport(clientSide) == errNatPort,
    "and its quote is rewritten to the public form the peer outside will recognise");

// The MUST-support pair is what this path claims: REQ-10a's two types. A Redirect is one of the MAYs and
// must keep taking the ordinary path even when its quote is nonsense.
var redirect = Frame(1, server, wan, Error(5, 0, new byte[12]));
Expect(errTable.Translate(redirect.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.None,
    "a Redirect is not claimed by this path at all");
var truncated = Frame(1, server, wan, Error(3, 4, new byte[6]));
Expect(errTable.Translate(truncated.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.Discard,
    "an error with less than a header quoted is dropped rather than read past its end");

// REQ-6: an error about an ICMP query MUST NOT refresh the session it quotes, and MUST NOT delete it.
var queryTable = new NatTable(wan, lanAddr, lanMask, () => clock.Now);
var errPing = Frame(1, client, server, Icmp(8, 0x2222));
queryTable.Translate(errPing.AsSpan(), WanIfIdx, WanIfIdx);
var errPingId = IcmpId(errPing);
// A fresh packet each time: the first one comes back with its quote already reverted, and feeding that
// copy through again would be a test of the second run rather than of this rule.
byte[] AboutPing() => Frame(1, server, wan, Error(11, 0, Quote(1, wan, server, Icmp(8, errPingId))));
Expect(queryTable.Translate(AboutPing().AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.IcmpError
       && queryTable.FlowCount == 1,
    "the error about a query is translated, and the session it quotes survives being quoted");
clock.Now = start + TimeSpan.FromSeconds(90);
queryTable.Translate(AboutPing().AsSpan(), WanIfIdx, WanIfIdx);
queryTable.Sweep();
Expect(queryTable.FlowCount == 0,
    "the same error past the ICMP session timer does not hold that timer open (REQ-6 MUST NOT refresh)");

// The control that makes the line above say something: an error quoting TCP does refresh, and a flow held
// open only by that refresh cannot be swept for the same reason.
var errTcpTable = new NatTable(wan, lanAddr, lanMask, () => clock.Now);
var handshake = Frame(6, client, server, Tcp(4010, 443, 0x02));
errTcpTable.Translate(handshake.AsSpan(), WanIfIdx, WanIfIdx);
var tcpNat = Sport(handshake);
clock.Now = start + TimeSpan.FromMinutes(130);
var aboutTcp = Frame(1, server, wan, Error(3, 4, Quote(6, wan, server, Tcp(tcpNat, 443, 0x10))));
Expect(errTcpTable.Translate(aboutTcp.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.IcmpError,
    "an error about a TCP segment is translated too");
errTcpTable.Sweep();
Expect(errTcpTable.FlowCount == 1,
    "and the mapping survives the sweep, because the flow's own timer was last seen at this packet");

// --- every fragment of a datagram, not only the one that carries the header ----------------------
// RFC 791 §3.2 makes (protocol, source, destination, id) what the far host reassembles on, so the
// fragments behind the first are addressed to the client and are not rewritten by anything that reads
// ports. RFC 4787 §11 REQ-14 puts the obligation on the NAT to support receiving them in and out of
// order, and REQ-14a bounds what that support may cost.
var fragTable = new NatTable(wan, lanAddr, lanMask, () => clock.Now);
var tailPayload = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 };

var head = Frame(17, client, server, Udp(4010, 53), id: 7000, moreFragments: true);
Expect(fragTable.Translate(head.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.Snat && Src(head) == wan,
    $"the fragment that carries the UDP header is source-NATed like any other packet of the flow, got {A(Src(head))}");
var fragNatPort = Sport(head);

// The record is what a fragment behind the first is matched with, so an unfragmented datagram must not
// leave one: a table that stored every packet's rewrite would fill with entries nobody asks for and then
// refuse the fragmented ones, which is exactly the DoS shape REQ-14a tells a NAT not to build.
var whole = Frame(17, client, server, Udp(4010, 53), id: 7001);
Expect(fragTable.Translate(whole.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.Snat,
    "a datagram with nothing behind it is translated and needs no record");
Expect(fragTable.FragmentCount == 1,
    $"only the datagram with MF set is recorded, got {fragTable.FragmentCount} records");

var tail = Frame(17, client, server, tailPayload, id: 7000, fragmentOffset: 100);
var tailOutcome = fragTable.Translate(tail.AsSpan(), WanIfIdx, WanIfIdx);
Expect(tailOutcome.Action == NatAction.Snat && Src(tail) == wan,
    $"the fragment behind the first follows its datagram's rewrite, got {A(Src(tail))} and {tailOutcome.Action}");
Expect(Dst(tail) == server, "and only the half this table owns changes: the destination was never ours");
Expect(tail.AsSpan(20, 8).SequenceEqual(tailPayload),
    "nothing at its offset is read as a transport header - it is somebody's payload, and rewriting it would corrupt the datagram");
Expect((FlagsAndOffset(tail) & 0x1FFF) == 100 && DatagramId(tail) == 7000,
    "the offset and the id the far host reassembles on come out of the rewrite untouched");
Expect(fragTable.FragmentRewrites == 1, $"the rewrite is counted, got {fragTable.FragmentRewrites}");

// The record belongs to the datagram, not to one offset of it: every fragment behind the first carries a
// different offset and follows the same rewrite. A different id is a different datagram, and an id this
// table never saw has no rewrite to inherit.
var secondTail = Frame(17, client, server, tailPayload, id: 7000, fragmentOffset: 300);
Expect(fragTable.Translate(secondTail.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.Snat
       && Src(secondTail) == wan,
    $"a further fragment of the same datagram follows the same record, got {A(Src(secondTail))}");
var neighbour = Frame(17, client, server, tailPayload, id: 7002, fragmentOffset: 100);
var neighbourBefore = fragTable.Fragments;
Expect(fragTable.Translate(neighbour.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.None
       && Src(neighbour) == client && fragTable.Fragments == neighbourBefore + 1,
    "a fragment of a different datagram id is not rewritten from its neighbour's record");

// The other direction, where the rewrite is the one the answer already got: the far host fragments its
// reply for the path, and only the first of those fragments carries the port this table matched on.
var replyTable = new NatTable(wan, lanAddr, lanMask, () => clock.Now);
var probe = Frame(17, client, server, Udp(4011, 53));
Expect(replyTable.Translate(probe.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.Snat,
    "the query that opens the flow is translated");
var probeNatPort = Sport(probe);
var answerHead = Frame(17, server, wan, Udp(53, probeNatPort), id: 9100, moreFragments: true);
Expect(replyTable.Translate(answerHead.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.Dnat
       && Dst(answerHead) == client,
    "the answer's first fragment is destination-NATed to the client");
var answerTail = Frame(17, server, wan, tailPayload, id: 9100, fragmentOffset: 200);
var answerTailOutcome = replyTable.Translate(answerTail.AsSpan(), WanIfIdx, WanIfIdx);
Expect(answerTailOutcome.Action == NatAction.Dnat && Dst(answerTail) == client,
    $"and so is the fragment behind it, got {A(Dst(answerTail))} and {answerTailOutcome.Action}");
Expect(Src(answerTail) == server, "its source is the server's, which the client's own socket has to keep matching");

// A fragment whose first one never came this way - lost on the way, or a datagram this table does not
// forward - is not guessed at: with no rewrite on hand there is no address to write that is not invented.
var orphanTable = new NatTable(wan, lanAddr, lanMask, () => clock.Now);
var orphanBefore = orphanTable.Fragments;
var orphan = Frame(17, client, server, tailPayload, id: 1234, fragmentOffset: 100);
Expect(orphanTable.Translate(orphan.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.None
       && orphanTable.Fragments == orphanBefore + 1 && Src(orphan) == client,
    "a fragment of an unseen datagram is forwarded as it arrived and counted");

// A datagram id is reused by a flow that is still alive, so the record has to live as long as the traffic
// does, not as long as the first fragment that happened to be seen first. Past the window, though,
// nobody is reassembling that datagram any more - and a stale record is how a reused id picks up
// somebody else's address.
clock.Now = clock.Now.AddSeconds(40);
var headAgain = Frame(17, client, server, Udp(4010, 53), id: 7000, moreFragments: true);
Expect(fragTable.Translate(headAgain.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.Snat,
    "the same datagram id comes round again on a flow that is still alive");
clock.Now = clock.Now.AddSeconds(40);
fragTable.Sweep();
Expect(fragTable.FragmentCount == 1,
    $"and its record is refreshed rather than aged out, got {fragTable.FragmentCount}");
var kept = Frame(17, client, server, tailPayload, id: 7000, fragmentOffset: 100);
Expect(fragTable.Translate(kept.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.Snat && Src(kept) == wan,
    $"so a fragment 80 seconds after its head is still rewritten, got {A(Src(kept))}");
clock.Now = clock.Now.AddSeconds(61);
fragTable.Sweep();
Expect(fragTable.FragmentCount == 0, $"and once it goes quiet for a whole window the record is gone, got {fragTable.FragmentCount}");
var late = Frame(17, client, server, tailPayload, id: 7000, fragmentOffset: 100);
Expect(fragTable.Translate(late.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.None && Src(late) == client,
    "the fragment that arrives after its datagram's record is gone is not rewritten from a stale mapping");

// --- the driver's shutdown modes are bit values, and they were one off ---------------------------
// windivert.h: WINDIVERT_SHUTDOWN_RECV = 0x1, _SEND = 0x2, _BOTH = 0x3. Declared 0/1/2, "shut down the
// receive side" passed 0 and was rejected, so a thread blocked inside WinDivertRecv could never be
// released: Ctrl+C left the process alive with its handles still diverting everything the filters
// matched, and a diverted packet that is not reinjected is dropped rather than bounced back.
Expect((int)TlsMitm.WinDivertPInvoke.ShutdownMode.Recv == 0x1, "ShutdownMode.Recv is 0x1, as windivert.h defines it");
Expect((int)TlsMitm.WinDivertPInvoke.ShutdownMode.Send == 0x2, "ShutdownMode.Send is 0x2, as windivert.h defines it");
Expect((int)TlsMitm.WinDivertPInvoke.ShutdownMode.Both == 0x3, "Both is the union of the two, so 0x3");

// --- the proxy's LAN capture filter, as WinDivert itself parses it -------------------------------
// A forwarded client is picked up at the forward layer, where the source subnet is the only stable
// field: the index there is the egress (measured). The string is compiled by the driver's own parser
// for the layer it will be opened at, so a clause that layer rejects fails here instead of at a live
// start, and the bounds are asserted because they are what keeps the filter on the LAN's traffic.
var lanSide = new TlsMitm.LanSide(System.Net.IPAddress.Parse("192.168.122.1"),
    System.Net.IPAddress.Parse("192.168.122.0"), System.Net.IPAddress.Parse("192.168.122.255"), 5);
Expect(lanSide.TcpFilter.Contains("ip.SrcAddr >= 192.168.122.0"), $"the LAN filter's lower bound is the subnet's first address, got '{lanSide.TcpFilter}'");
Expect(lanSide.TcpFilter.Contains("ip.SrcAddr <= 192.168.122.255"), "and its upper bound is the subnet's last address");
Expect(!lanSide.TcpFilter.Contains("DstPort"), "no port takes part in it: a port clause would be detection by port");
Expect(lanSide.UdpFilter.Contains("ip.SrcAddr >= 192.168.122.0"), "the UDP leg is bounded to the same subnet");
Expect(lanSide.UdpFilter.Contains("udp") && !lanSide.UdpFilter.Contains("tcp"), "and it names udp, not tcp");
Expect(CompilesForward(lanSide.TcpFilter, out var tcpFilterError), $"WinDivert compiles the TCP filter at the forward layer{(tcpFilterError is null ? "" : $": {tcpFilterError}")}");
Expect(CompilesForward(lanSide.UdpFilter, out var udpFilterError), $"WinDivert compiles the UDP filter at the forward layer{(udpFilterError is null ? "" : $": {udpFilterError}")}");

// The rewrite changes words that every TCP and UDP checksum covers, and for a fragment the rest of the
// datagram is not on hand to recompute over - so the table folds them in itself (RFC 1624 §2). The far
// host is the judge: what it verifies is the reassembled datagram against the addresses now in the
// fragment headers, so that is what is checked here, computed independently by the test's own helper.
var csumTable = new NatTable(wan, lanAddr, lanMask, () => clock.Now);
var payload16 = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
var udpAcrossFrags = Udp(4040, 53);
WriteUdpLength(udpAcrossFrags, (ushort)(8 + payload16.Length));
WriteUdpChecksum(udpAcrossFrags, UdpChecksum(client, server, udpAcrossFrags, payload16));
var fragHead = Frame(17, client, server, [.. udpAcrossFrags, .. payload16.AsSpan(0, 8)], id: 7200, moreFragments: true);
Expect(csumTable.Translate(fragHead.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.Snat,
    "a first fragment of a datagram whose checksum really was computed is translated");
var fragTail = Frame(17, client, server, [.. payload16.AsSpan(8)], id: 7200, fragmentOffset: 2);
Expect(csumTable.Translate(fragTail.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.Snat,
    "and so is the fragment that carries the octets behind it");
var reassembled = new byte[8 + payload16.Length];
fragHead.AsSpan(20, 16).CopyTo(reassembled);
payload16.AsSpan(8).CopyTo(reassembled.AsSpan(16));
Expect(BinaryPrimitives.ReadUInt16BigEndian(reassembled.AsSpan(6, 2))
       == UdpChecksum(Src(fragHead), Dst(fragHead), [.. reassembled.AsSpan(0, 8)], reassembled.AsSpan(8)),
    "and the datagram that reassembles at the far end validates against the address and port this table wrote");

// The answer's own fragments: the server computed its checksum over the public tuple it can see, and this
// rewrite moves both the destination address and the destination port out from under it.
var mappedPort = Sport(fragHead);
var replyAcross = Udp(53, mappedPort);
WriteUdpLength(replyAcross, (ushort)(8 + payload16.Length));
WriteUdpChecksum(replyAcross, UdpChecksum(server, wan, replyAcross, payload16));
var replyFragHead = Frame(17, server, wan, [.. replyAcross, .. payload16.AsSpan(0, 8)], id: 7201, moreFragments: true);
Expect(csumTable.Translate(replyFragHead.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.Dnat,
    "the answer's first fragment is destination-NATed");
var replyFragTail = Frame(17, server, wan, [.. payload16.AsSpan(8)], id: 7201, fragmentOffset: 2);
Expect(csumTable.Translate(replyFragTail.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.Dnat,
    "and so is the fragment behind it");
var replyReassembled = new byte[8 + payload16.Length];
replyFragHead.AsSpan(20, 16).CopyTo(replyReassembled);
payload16.AsSpan(8).CopyTo(replyReassembled.AsSpan(16));
Expect(BinaryPrimitives.ReadUInt16BigEndian(replyReassembled.AsSpan(6, 2))
       == UdpChecksum(Src(replyFragHead), Dst(replyFragHead),
           [.. replyReassembled.AsSpan(0, 8)], replyReassembled.AsSpan(8)),
    "and the client reassembles an answer whose checksum covers the private tuple it was written into");

// The same for TCP, where the field sits 10 octets further into the segment: write it at the UDP offset
// and the fold lands on the sequence number instead.
var tcpPayload = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
var tcpTransport = new byte[24];
Tcp(4050, 443, 0x18).CopyTo(tcpTransport);
BinaryPrimitives.WriteUInt32BigEndian(tcpTransport.AsSpan(4), 0x11223344u);
BinaryPrimitives.WriteUInt32BigEndian(tcpTransport.AsSpan(8), 0x55667788u);
tcpPayload.AsSpan(0, 4).CopyTo(tcpTransport.AsSpan(20));
var tcpSegment = new byte[32];
tcpTransport.CopyTo(tcpSegment);
tcpPayload.AsSpan(4).CopyTo(tcpSegment.AsSpan(24));
WriteTcpChecksum(tcpSegment, TcpChecksum(client, server, tcpSegment));
var tcpHead = tcpSegment[..24];
var tcpFrag = Frame(6, client, server, tcpHead, id: 7300, moreFragments: true);
Expect(csumTable.Translate(tcpFrag.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.Snat,
    "a first fragment of a TCP segment is translated");
var tcpTail = Frame(6, client, server, [.. tcpPayload.AsSpan(4)], id: 7300, fragmentOffset: 3);
Expect(csumTable.Translate(tcpTail.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.Snat,
    "and so is the fragment behind it");
tcpFrag.AsSpan(20, 24).CopyTo(tcpSegment);
Expect(BinaryPrimitives.ReadUInt16BigEndian(tcpSegment.AsSpan(16, 2))
       == TcpChecksum(Src(tcpFrag), Dst(tcpFrag), tcpSegment)
       && BinaryPrimitives.ReadUInt32BigEndian(tcpSegment.AsSpan(4)) == 0x11223344u,
    "and the reassembled segment validates while its sequence number is still the sender's: a fold written at the wrong offset lands inside the data this checksum covers, and the two errors cancel each other out, so the number alone cannot show it");
Expect(BinaryPrimitives.ReadUInt32BigEndian(tcpFrag.AsSpan(24, 4)) == 0x11223344u
       && BinaryPrimitives.ReadUInt32BigEndian(tcpFrag.AsSpan(28, 4)) == 0x55667788u,
    "and the fold landed on the checksum field, not on the sequence and acknowledgement numbers next to it");

// A UDP checksum field of zero says the sender did not compute one (RFC 768), so there is nothing to
// update - and folding would leave a non-zero field claiming to be a checksum the sender never made.
var unchecksummed = Frame(17, client, server, Udp(4060, 53), id: 7400, moreFragments: true);
Expect(csumTable.Translate(unchecksummed.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.Snat
       && BinaryPrimitives.ReadUInt16BigEndian(unchecksummed.AsSpan(26, 2)) == 0,
    "a datagram sent with no UDP checksum is rewritten without one being invented for it");

// ICMP is the third transport this table maps, and the one whose checksum has no pseudo-header over the
// addresses (RFC 791 §3.1 leaves it over the message), so a rewrite that folded the addresses into it
// would corrupt a checksum that was right. A big ping is what puts a datagram like this in fragments.
var pingData = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
var pingMessage = new byte[24];
Icmp(8, 4711).CopyTo(pingMessage);
pingData.CopyTo(pingMessage.AsSpan(8));
WriteIcmpChecksum(pingMessage, IcmpChecksum(pingMessage));
var icmpFrag = Frame(1, client, server, pingMessage[..16], id: 7500, moreFragments: true);
Expect(csumTable.Translate(icmpFrag.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.Snat,
    "a first fragment of a ping bigger than the path is translated");
var icmpTail = Frame(1, client, server, pingData[8..], id: 7500, fragmentOffset: 2);
Expect(csumTable.Translate(icmpTail.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.Snat,
    "and so are the octets behind it");
icmpFrag.AsSpan(20, 16).CopyTo(pingMessage);
pingData[8..].CopyTo(pingMessage.AsSpan(16));
Expect(BinaryPrimitives.ReadUInt16BigEndian(pingMessage.AsSpan(2, 2)) == IcmpChecksum(pingMessage),
    "and the reassembled message still adds up on its own terms, with the identifier this table mapped inside it");

// --- what the driver's own checksum helper does to a fragment ------------------------------------
// Router leaves an unfragmented packet's transport checksum to WinDivertHelperCalcChecksums and folds a
// first fragment's itself. That division of labour is a property of this driver rather than of the
// standards, so it is pinned by asking the driver: an update that began recomputing a partial datagram
// would overwrite the fold with a checksum over the first fragment alone, and one that wrote into a
// non-first fragment would corrupt somebody's payload.
static int CalcInto(byte[] packet)
{
    unsafe
    {
        fixed (byte* p = packet)
        {
            TlsMitm.WinDivertPInvoke.WinDivertHelperCalcChecksums(p, packet.Length, null,
                TlsMitm.WinDivertPInvoke.ChecksumsFlag.All);
        }
    }
    return BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(26, 2));
}
var plain = Frame(17, client, server, Udp(4070, 53));
Expect(CalcInto(plain) == UdpChecksum(client, server, Udp(4070, 53), [])
       && Csum(plain.AsSpan(0, 20)) == 0,
    "the driver computes the transport checksum of an unfragmented datagram, and its header checksum");
var firstFrag = Frame(17, client, server, Udp(4070, 53), moreFragments: true);
BinaryPrimitives.WriteUInt16BigEndian(firstFrag.AsSpan(26, 2), 0x1234);
Expect(CalcInto(firstFrag) == 0x1234 && Csum(firstFrag.AsSpan(0, 20)) == 0,
    "on a first fragment it leaves the transport checksum it cannot compute and still fixes the header");
var laterFrag = Frame(17, client, server, tailPayload, fragmentOffset: 2);
Expect(CalcInto(laterFrag) == 0x1122 && laterFrag.AsSpan(20, 8).SequenceEqual(tailPayload),
    "and on a fragment behind the first it writes nothing into the payload");
var dfPacket = Frame(17, client, server, Udp(4071, 53), dontFragment: true);
Expect(CalcInto(dfPacket) == UdpChecksum(client, server, Udp(4071, 53), [])
       && Csum(dfPacket.AsSpan(0, 20)) == 0,
    "and it computes the checksum of a datagram with DF set, which is not a fragment and most of the modern path is that");

// --- a WAN that renews its lease ----------------------------------------------------------------------
// The address a SNAT writes is the one the WAN interface holds, and a running program does not get to
// assume it stays put: a DHCP renew, or the phone hotspot this router is usually pointed at
// reassociating, hands out a different one while packets are still going. Keeping the address read at
// startup makes every flow this program forwards a spoofed source as far as the upstream is concerned.
var moved = NatTable.ParseAddress("203.0.113.77");
var flowsBeforeMove = table.FlowCount;
table.SetWanAddress(moved);
Expect(table.WanAddress == moved, $"the table reads back the address it was given, got {A(table.WanAddress)}");
Expect(table.FlowCount == flowsBeforeMove,
    "and no mapping is lost by the move, because none of them is keyed on this host's own address");

var afterMove = Frame(6, client, server, Tcp(4020, 443, 0x02));
Expect(table.Translate(afterMove.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.Snat
       && Src(afterMove) == moved,
    $"a flow that starts after the change leaves with the address the interface has now, got {A(Src(afterMove))}");

// The mappings have to survive it, not just stay counted: RFC 4787 REQ-1 makes the mapping
// endpoint-independent, so the port is the whole key and the address this host answers on is not part of
// it. Both halves of the reply move together, since it is the same address the reply leg's filter is made
// from.
var preMoveReply = Frame(6, server, moved, Tcp(443, natPort, 0x12));
Expect(table.Translate(preMoveReply.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.Dnat
       && Dst(preMoveReply) == client && Dport(preMoveReply) == 4000,
    $"a mapping opened before the change still answers on the new address, got {A(Dst(preMoveReply))}:{Dport(preMoveReply)}");
var staleReply = Frame(6, server, wan, Tcp(443, natPort, 0x12));
Expect(table.Translate(staleReply.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.None,
    "and the address the interface gave up is not one this table takes replies on");

// The one thing a move does not carry over is the memory of what left under the old address. A notice
// quotes that address, this table knows only the one it has now, and so the quote names neither the WAN
// nor a LAN client. The session it quotes is broken at the peer the moment its source moves - that is
// what a renewed address does to a connection - so what goes missing here is the notice, not the flow.
var movedErrTable = new NatTable(wan, lanAddr, lanMask, () => clock.Now);
var leftBeforeMove = Frame(17, client, server, Udp(4021, 4022));
movedErrTable.Translate(leftBeforeMove.AsSpan(), WanIfIdx, WanIfIdx);
movedErrTable.SetWanAddress(moved);
var oldQuote = Frame(1, server, moved, Error(3, 4, Quote(17, wan, server, Udp(Sport(leftBeforeMove), 4022))));
Expect(movedErrTable.Translate(oldQuote.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.Discard
       && movedErrTable.IcmpErrorsDropped == 1,
    "an error quoting a datagram that left under the address this host no longer holds is dropped");
var newQuote = Frame(1, server, moved, Error(3, 4, Quote(17, moved, server, Udp(Sport(leftBeforeMove), 4022))));
Expect(movedErrTable.Translate(newQuote.AsSpan(), WanIfIdx, WanIfIdx).Action == NatAction.IcmpError
       && Dst(newQuote) == client && QSrc(newQuote) == client,
    "the same notice about a datagram that left under the current address still reaches the client it is for");

foreach (var note in notes) Console.WriteLine($"[natcheck] {note}");
if (failures.Count > 0)
{
    Console.WriteLine($"[natcheck] FAIL ({failures.Count})");
    foreach (var failure in failures) Console.WriteLine($"[natcheck]   {failure}");
    return 1;
}
Console.WriteLine($"[natcheck] PASS - {notes.Count} NAT assertions, snat={table.Snats} dnat={table.Dnats}");
return 0;

static bool CompilesForward(string filter, out string? error)
{
    unsafe
    {
        var compiled = stackalloc byte[4096];
        var ok = TlsMitm.WinDivertPInvoke.WinDivertHelperCompileFilter(
            filter, TlsMitm.WinDivertPInvoke.Layer.Forward, compiled, 4096, out var at, out _);
        error = ok ? null : System.Runtime.InteropServices.Marshal.PtrToStringAnsi(at);
        return ok;
    }
}

void Expect(bool ok, string what)
{
    if (ok) notes.Add($"ok {what}");
    else failures.Add(what);
}

static string A(uint address) => NatTable.FormatAddress(address);

static int Ihl(byte[] packet) => (packet[0] & 0x0F) * 4;
static uint Src(byte[] packet) => BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(12, 4));
static uint Dst(byte[] packet) => BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(16, 4));
static ushort Sport(byte[] packet) => BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(Ihl(packet), 2));
static ushort Dport(byte[] packet) => BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(Ihl(packet) + 2, 2));
static ushort IcmpId(byte[] packet) => BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(Ihl(packet) + 4, 2));
static ushort DatagramId(byte[] packet) => BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(4, 2));
static ushort FlagsAndOffset(byte[] packet) => BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(6, 2));

static byte[] Frame(byte proto, uint src, uint dst, byte[] transport, int fragmentOffset = 0, ushort id = 0, bool moreFragments = false, bool dontFragment = false)
{
    var packet = new byte[20 + transport.Length];
    packet[0] = 0x45;
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), (ushort)packet.Length);
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4, 2), id);
    var flagsAndOffset = (ushort)(fragmentOffset & 0x3FFF);
    if (moreFragments) flagsAndOffset |= 0x2000;
    if (dontFragment) flagsAndOffset |= 0x4000;
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(6, 2), flagsAndOffset);
    packet[8] = 64;
    packet[9] = proto;
    BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(12, 4), src);
    BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(16, 4), dst);
    transport.CopyTo(packet, 20);
    return packet;
}

static byte[] Tcp(ushort sport, ushort dport, byte flags)
{
    var header = new byte[20];
    BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(0, 2), sport);
    BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(2, 2), dport);
    header[12] = 5 << 4;
    header[13] = flags;
    BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(14, 2), 64240);
    return header;
}

static byte[] Udp(ushort sport, ushort dport)
{
    var header = new byte[8];
    BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(0, 2), sport);
    BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(2, 2), dport);
    BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4, 2), 8);
    return header;
}

static byte[] Icmp(byte type, ushort identifier)
{
    var header = new byte[8];
    header[0] = type;
    BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4, 2), identifier);
    return header;
}

// An error's own header is type, code, checksum and the four octets RFC 4884 §4.1 turned into a length
// over the quoted packet; the quoted packet follows immediately (RFC 791 §3.1).
static byte[] Error(byte type, byte code, byte[] quoted, uint unused = 0)
{
    var message = new byte[8 + quoted.Length];
    message[0] = type;
    message[1] = code;
    BinaryPrimitives.WriteUInt32BigEndian(message.AsSpan(4, 4), unused);
    quoted.CopyTo(message, 8);
    return message;
}

// The quote a NAT has to revert: the internet header with a checksum that really adds up - REQ-3a makes
// a drop of the whole error the answer when it does not, so a fixture that fakes it proves nothing - plus
// the first 64 bits of the transport header.
static byte[] Quote(byte proto, uint src, uint dst, byte[] transport, byte[]? options = null)
{
    var head = new byte[20 + (options?.Length ?? 0)];
    head[0] = (byte)(0x40 | head.Length / 4);
    BinaryPrimitives.WriteUInt16BigEndian(head.AsSpan(2, 2), (ushort)(head.Length + Math.Min(transport.Length, 8)));
    head[8] = 64;
    head[9] = proto;
    BinaryPrimitives.WriteUInt32BigEndian(head.AsSpan(12, 4), src);
    BinaryPrimitives.WriteUInt32BigEndian(head.AsSpan(16, 4), dst);
    if (options is not null) options.CopyTo(head, 20);
    var quoted = new byte[head.Length + Math.Min(transport.Length, 8)];
    head.CopyTo(quoted, 0);
    transport.AsSpan(0, Math.Min(transport.Length, 8)).CopyTo(quoted.AsSpan(head.Length));
    BinaryPrimitives.WriteUInt16BigEndian(quoted.AsSpan(10, 2), Csum(quoted.AsSpan(0, head.Length)));
    return quoted;
}

static int QuoteAt(byte[] packet) => Ihl(packet) + 8;
static int QuoteIhl(byte[] packet) => (packet[QuoteAt(packet)] & 0x0F) * 4;
static byte[] QuotedHeader(byte[] packet) => packet.AsSpan(QuoteAt(packet), QuoteIhl(packet)).ToArray();
static byte[] QuotedTransport(byte[] packet) => packet.AsSpan(QuoteAt(packet) + QuoteIhl(packet), 8).ToArray();
static uint QSrc(byte[] packet) => BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(QuoteAt(packet) + 12, 4));
static uint QDst(byte[] packet) => BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(QuoteAt(packet) + 16, 4));
static ushort QSport(byte[] packet) => BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(QuoteAt(packet) + QuoteIhl(packet), 2));
static ushort QDport(byte[] packet) => BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(QuoteAt(packet) + QuoteIhl(packet) + 2, 2));
static ushort QChecksum(byte[] packet) => BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(QuoteAt(packet) + QuoteIhl(packet) + 6, 2));

static void WriteUdpLength(byte[] header, ushort length) => BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4, 2), length);
static void WriteUdpChecksum(byte[] header, ushort checksum) => BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(6, 2), checksum);

// RFC 768's pseudo-header (the two addresses, zero, the protocol, the UDP length) over the header with its
// checksum field clear and the payload, summed with the form below. The payload stands in for everything a
// quote leaves out, which is exactly what makes the product's fold worth checking against a fresh value.
static ushort UdpChecksum(uint src, uint dst, byte[] header, ReadOnlySpan<byte> payload)
{
    header = (byte[])header.Clone();
    BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(6, 2), 0);
    var block = new byte[12 + header.Length + payload.Length];
    BinaryPrimitives.WriteUInt32BigEndian(block.AsSpan(0, 4), src);
    BinaryPrimitives.WriteUInt32BigEndian(block.AsSpan(4, 4), dst);
    block[9] = 17;
    BinaryPrimitives.WriteUInt16BigEndian(block.AsSpan(10, 2), BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(4, 2)));
    header.CopyTo(block, 12);
    payload.CopyTo(block.AsSpan(12 + header.Length));
    return Csum(block);
}

// RFC 1071 §1.4's pseudo-header for TCP: protocol 6 and the length of the whole segment, which for a
// fragmented one is the head's transport area plus the octets in the fragments behind it. The segment
// arrives here already reassembled, since that is what the checksum covers and what the far host verifies.
static ushort TcpChecksum(uint src, uint dst, ReadOnlySpan<byte> segment)
{
    var copy = segment.ToArray();
    BinaryPrimitives.WriteUInt16BigEndian(copy.AsSpan(16, 2), 0);
    var block = new byte[12 + copy.Length];
    BinaryPrimitives.WriteUInt32BigEndian(block.AsSpan(0, 4), src);
    BinaryPrimitives.WriteUInt32BigEndian(block.AsSpan(4, 4), dst);
    block[9] = 6;
    BinaryPrimitives.WriteUInt16BigEndian(block.AsSpan(10, 2), (ushort)copy.Length);
    copy.CopyTo(block, 12);
    return Csum(block);
}

static void WriteTcpChecksum(byte[] segment, ushort checksum) =>
    BinaryPrimitives.WriteUInt16BigEndian(segment.AsSpan(16, 2), checksum);

// RFC 791 §3.1: the ICMP checksum covers the message and nothing else - no pseudo-header over the two
// addresses, which is the difference a NAT has to respect when it rewrites them.
static ushort IcmpChecksum(ReadOnlySpan<byte> message)
{
    var copy = message.ToArray();
    BinaryPrimitives.WriteUInt16BigEndian(copy.AsSpan(2, 2), 0);
    return Csum(copy);
}

static void WriteIcmpChecksum(byte[] message, ushort checksum) =>
    BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(2, 2), checksum);

// The test's own checksum helper is RFC 1071 §1.4's accumulation in 32-bit words - deliberately not the
// shape the product uses, so the two cannot share a mistake and still agree. Keeping the accumulator wide
// is not cosmetic: five full words of a 20-octet header overflow 32 bits, and a carry lost there is a
// checksum off by one in the folded sum. That is exactly how this fixture first failed.
static ushort Csum(ReadOnlySpan<byte> data)
{
    ulong sum = 0;
    var i = 0;
    for (; i + 3 < data.Length; i += 4) sum += BinaryPrimitives.ReadUInt32BigEndian(data.Slice(i, 4));
    if (i + 1 < data.Length) sum += BinaryPrimitives.ReadUInt16BigEndian(data.Slice(i, 2));
    if (i < data.Length) sum += (uint)data[i] << 8;
    while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
    return (ushort)(~sum & 0xFFFF);
}

internal sealed class FakeClock
{
    public DateTime Now { get; set; } = new(2026, 10, 26, 12, 0, 0, DateTimeKind.Utc);
}
