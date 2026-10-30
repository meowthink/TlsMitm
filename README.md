# TlsMitm [![ci](https://github.com/meowthink/TlsMitm/actions/workflows/ci.yml/badge.svg)](https://github.com/meowthink/TlsMitm/actions/workflows/ci.yml)[![release](https://github.com/meowthink/TlsMitm/actions/workflows/release.yml/badge.svg)](https://github.com/meowthink/TlsMitm/actions/workflows/release.yml)

Transparent TLS interception for Windows. Every outbound TCP connection is captured with
WinDivert, redirected to a local proxy, terminated with a certificate this machine can sign, and
relayed to the real server. The client sees an ordinary TLS session; the plaintext is written to a
pcap. No client configuration, no explicit proxy, no port rules.

Fiddler Classic solves much of this on Windows, and its HTTPS tab — decrypt for all processes,
leaves signed by a local root — is the reference for the workflow here. But Classic is closed
source, Windows-only, and since [Fiddler
Everywhere](https://www.telerik.com/blogs/new-release-fiddler-everywhere-3) became the product
Telerik actually sells, it only receives maintenance; as a proxy it also only reaches clients that
can be pointed at it. Capturing at the packet layer removes that limit and makes the rest possible:
STARTTLS/FTPS upgraded in place, ECH downgrade with a blind fallback, QUIC pushed back to TCP,
per-client chain selection, a local CRL, and plain pcap output.

## How it does it

1. WinDivert filter `outbound and tcp and not impostor` sees every SYN. The connection is remembered
   by its full 4-tuple (RFC 793 §3.1) and given a token from RFC 6335 §5.2.1's dynamic range, which
   replaces the client's source port as the packet is rewritten to the relay port `8443` (addresses
   swapped, so it arrives at the proxy as inbound for the client's own address); the token names one
   flow on the accepted socket, and the reply leg puts the client's real port back. The impostor flag
   keeps the rewrite from being captured again.
2. The proxy peeks the first byte on both sockets. `0x16` is implicit TLS. A server-first protocol
   (SMTP/IMAP/POP3/FTP) stays plaintext and is scanned for `STARTTLS` / `STLS` / `AUTH TLS`; after
   the server's readiness reply the same TCP connection is upgraded in place.
3. For TLS the ClientHello is parsed (SNI, ALPN, `early_data`, PSK, ECH, GREASE), the signing chain
   is chosen by the process that owns the client socket, and the session is terminated toward the
   client and re-originated toward the server. A hello the real server refuses is not fatal: the
   client's own hello is replayed on a fresh connection and that session goes blind.
4. ECH hellos are terminated with a leaf for the public name, which is what makes Chromium either
   keep the session or retry without ECH. Only a failed client leg convicts the host: an idle
   terminated session proves nothing, because a GREASE-ECH client (RFC 9849 §6.2.1) finishes the
   handshake and then sits quiet. A host goes blind for 10 minutes on a failed handshake, not on
   silence, so the site keeps working without losing interception around every page load.
5. 0-RTT and PSK-only resumptions are relayed blind: decryption would need keys we cannot have.
   They are still captured, as is every other TLS session (`captures/<host>_<time>_<id>.pcap`).
   Each file opens with a synthesized three-way handshake, so Wireshark reads one connection from
   its start rather than a fragment out of the middle.
6. QUIC is dropped by long-header signature, so HTTP/3 clients fall back to TCP and stay visible.
7. Every Fiddler-root leaf carries a CRL distribution point served by the proxy itself on
   `http://127.0.0.1:8873/crl/<root-thumbprint>.crl`, so a validating client gets an answer.

## What it decrypts

Detection reads bytes, never ports: a connection whose first byte is `0x16` is implicit TLS whatever
port it uses, a server-first text protocol is scanned for the upgrade command, and a client-first
session is named by its own first octet — `0x30` for LDAP's BER, `<` for XMPP's XML. The protocol names
below are what the mechanism covers; no port table is consulted.

| protocol | how the upgrade is granted | result |
| --- | --- | --- |
| HTTPS, FTPS, IMAPS, POP3S, LDAPS, NNTPS, IRCS, XMPP direct TLS, SIPS | none — TLS from the first byte | terminated and decrypted |
| SMTP | `STARTTLS` → `220` (RFC 3207 §4) | upgraded in place |
| IMAP | `<tag> STARTTLS` → `<tag> OK` (RFC 9051 §6.2.1) | upgraded in place |
| POP3 | `STLS` → `+OK` (RFC 2595 §4) | upgraded in place |
| FTP | `AUTH TLS` → `234` (RFC 4217 §4.2), data channels per §7 | upgraded in place |
| NNTP | `STARTTLS` → `382` (RFC 4642 §2.2) | upgraded in place |
| LDAP | BER `ExtendedRequest` `1.3.6.1.4.1.1466.20037` → `ExtendedResponse` success (RFC 4511 §4.14) | upgraded in place |
| XMPP | `<starttls/>` → `<proceed/>` (RFC 6120 §5.4.2, boundary at the `>` per §5.4.2.3) | upgraded in place |
| any other TCP | — | relayed as it comes, not captured |

A session this proxy cannot read is not a broken one either: the two sockets keep carrying bytes, so
client and real server finish the handshake between themselves, and the plaintext simply stays inside
the packets instead of coming out of them. `ldap-bad` and `xmpp-bad` are the offline modes that hold the
proxy to that behaviour; `reject`, `ldap-decline` and `xmpp-decline` hold it to a server that really
refuses.

## Which chain, for which client

Two roots are usable, and no single chain satisfies both kinds of client:

| client | chain | why |
| --- | --- | --- |
| Windows/SChannel clients (Chromium network service, curl, .NET, svchost) | Fiddler root | they read the Windows store |
| Node, Electron main process, Node-type utilities | emSign intermediate | they only trust their bundled store |

`--emsign` maps the client's ephemeral port to a PID, reads its command line, and picks per
connection: emSign for Node/Electron, the Fiddler root for everything else; a GREASE-bearing
ClientHello from an ambiguous PID is treated as Chromium. A flow with no PID — every forwarded LAN
client, and any local flow the TCP table cannot name — gets emSign, the same chain `--emsign-only`
gives everyone.

## Prerequisites

* Windows 10/11 x64 and **administrator** (driver load and packet capture).
* **.NET 10 SDK** to build.
* A **Fiddler root CA with its private key installed** (the machine-wide `DO_NOT_TRUST_FiddlerRoot` is
  selected automatically).
* **WinDivert 2.2.2 x64** — `WinDivert.dll` + `WinDivert64.sys` are embedded in the assembly and
  unpacked on first run to `%APPDATA%\TlsMitm\windivert-2.2.2\x64` (LGPL-3.0, see
  `TlsMitm/windivert`). Nothing to install.
* **OpenSSL 3 x64** — `libssl-3-x64.dll` + `libcrypto-3-x64.dll` are embedded (Apache-2.0, see
  `TlsMitm/openssl/LICENSE.txt`) and unpacked to `%APPDATA%\TlsMitm\openssl-3`. The client-facing
  chain is only sent correctly by libssl, not by SChannel. A pair placed next to the executable
  overrides the embedded one.
* **emSign intermediates** (`TlsMitm/emsign_certs`) are only needed with `--emsign`, `--emsign-only`
  or `--rotate`.
* **Inbound reachability for the relay port.** A redirected connection reaches this host's own listener
  as an inbound TCP connection to 8443 whose source address is the server the client asked for, and
  Windows filters inbound (loopback is not, which is why a local service keeps answering while everything
  else hangs). With `--lan` the run asks this with a packet as it starts — one SYN from inside the LAN
  subnet to the relay, judged by the SYN-RECEIVED row the stack leaves in its TCP table when a listener
  takes a SYN — and stops if nothing does, instead of black-holing the LAN. The rule store is not
  consulted for that verdict: pre-defined service rules report their port field as a wildcard, and an
  explicit block rule outranks any allow rule, so the answer only the packet gives is the one that can be
  trusted. `--allow-relay-in` puts
  `tlsmitm-relay-in` in the store at startup and takes it back out when the run ends. The same rule can
  be made by hand; `RemoteAddress` cannot be narrowed, because that source is any server on the Internet.

`RootCa` looks for a Fiddler root in `CurrentUser` and `LocalMachine`, in both `Root` and `My` — the
trust anchor and the signing key do not have to live in the same store — and accepts only a copy it
can actually sign with. When there is none, `--init-ca` (elevated) creates one with the same shape as
the measured Fiddler root: CA=TRUE with pathLen 0, keyCertSign|cRLSign, serverAuth EKU, ~820 days,
key in `LocalMachine\My`, anchor in `LocalMachine\Root`. `tests\make-test-root.ps1` builds that same
fixture for CI and refuses to run while a usable root already exists, so `-Force` is the opt-in for
adding a second one. `starttlsprobe` signs with the machine root only when
`TLSMITM_CI_ROOT_STORE=LocalMachine` is set, as it is in CI; the `rootcheck` mode compares the root it
signed with against the one `RootCa` finds and fails if the two disagree.

## Build and run

```powershell
dotnet build TlsMitm
# elevated:
TlsMitm\bin\Debug\net10.0\TlsMitm.exe [--emsign | --emsign-only | --rotate] [--no-ech-downgrade]
    [--lan <ipv4>]
    [--root <pfx> | --root-thumbprint <thumbprint> | --init-ca]
    [--pid <pid,...> | --exclude-pid <pid,...>]
    [--process <name,...> | --exclude-process <name,...>]
```

| flag | effect |
| --- | --- |
| *(none)* | Fiddler chain for everyone; ECH downgrade on |
| `--emsign` | per-process chain selection; a client with no PID gets emSign |
| `--emsign-only` | emSign chain for every client |
| `--rotate` | alternate between the Fiddler root and the emSign intermediates |
| `--no-ech-downgrade` | relay ECH hellos blind instead of terminating them |
| `--init-ca` | create and install a root when discovery finds none (elevated); a usable root is reused |
| `--root <pfx>` | sign with a root from a PFX; password from `TLSMITM_ROOT_PASSWORD` |
| `--root-thumbprint <tp>` | sign with an installed root chosen by thumbprint |
| `--pid <pid,...>` | intercept only the flows owned by these processes |
| `--process <name,...>` | intercept only the flows owned by these executables |
| `--exclude-pid <pid,...>` | intercept everything except these processes |
| `--exclude-process <name,...>` | intercept everything except these executables |
| `--lan <ipv4>` | also intercept TCP a forwarded client sends from this address's subnet |
| `--allow-relay-in` | with `--lan`: add the inbound allow rule for the relay port, and remove it when the run ends |

Scoping is decided at the SYN that starts a flow, so an excluded process is passed through whole —
its packets are never rewritten, rather than half-intercepted. Each pair names a process by pid or by
executable, and an exclusion wins over an include.

`--lan` takes the same pipeline to a client that is not on this machine. The second capture point sits
at WinDivert's forward layer — packets the stack routes rather than delivers to or from this host —
with a filter bounded to that interface's subnet, because at this layer the interface index is the
egress (measured: the transit packets arrive with the outbound bit set and the WAN index). A matched
flow is rewritten exactly as a local one is, except that the destination becomes this host's LAN
address and the injected packet has to name that address's interface as the one it arrived on —
receive is strong-host, so a datagram arriving on one interface addressed to another's is discarded.
That is what makes the stack hand the packet to the
listener, and the socket, chain and relay below are the shared ones. A LAN client has no process here,
so `--emsign` gives it the emSign chain (see above), and `--pid`/`--process` only name local
processes, so they do not narrow a forwarded flow. Forwarding has to be on for that interface
(`Router --enable-forwarding`), while DHCP and DNS stay with Router.

UDP is captured on the same bounds for one purpose: a QUIC datagram, recognised by its packet signature
rather than a port, is dropped instead of routed, so the client falls back to the TCP above. Anything
else is handed back to the lower-priority handles and Router forwards it as usual. A fragmented TCP
datagram is left whole and unrewritten by the proxy: only the first fragment carries the header that names
the flow, and the upper-layer checksum covers the reassembled segment together with the addresses the
rewrite changes, so the pieces cannot be redirected one by one. That flow is therefore not intercepted —
with an MSS at or below the MTU a TCP segment is never fragmented — and the `PASS v4 fragment` line says
so; Router still translates every fragment of it, so the client's own traffic is not lost.

The console is mirrored to `tlsmitm-<yyyyMMdd-HHmmss>.log` next to the executable.

## Router

`Router/` is a second executable: a minimal stateful IPv4 NAT router between two of this host's interfaces,
with a DHCP pool and a resolver on the LAN side so a device plugged into it gets an address and answers to a
name. The interface holding the default gateway is the WAN side, the other one is the LAN side, and the
device's cable goes there. It can run next to `TlsMitm`, and the two share only the P/Invoke surface, which
`Router` links rather than copies.

```powershell
dotnet build Router
# elevated:
Router\bin\Debug\net10.0\Router.exe [--lan <ipv4>] [--wan <ipv4>] [--enable-forwarding] [--stop-ics]
    [--pool <ipv4>/<count>] [--scope <cidr>,<pool>/<count>,<router>[,<dns>]] [--lease <min>]
    [--udp-timeout <sec>] [--dns <ipv4>] [--no-dhcp] [--no-dns] [--allow-lan-in]
    [--trace <count>] [--stats <sec>]
```

| flag | effect |
| --- | --- |
| *(none)* | WAN = the one interface with a default gateway, LAN = the one other interface without one; each side ambiguous is a refusal that lists the candidates and their media type |
| `--lan <ipv4>` / `--wan <ipv4>` | pick the two sides by address instead |
| `--enable-forwarding` | turn on per-interface IPv4 forwarding, then run (reversible) |
| `--stop-ics` | stop Internet Connection Sharing for this run; a running `SharedAccess` is a refusal without it (undo with `Start-Service SharedAccess`) |
| `--allow-lan-in` | add the inbound allow rules for the listeners this run started — UDP on the ports they bound, TCP on 53 for the retry a truncated answer sends there — and remove them when the run ends |
| `--pool <ipv4>/<count>` | DHCP range (default: 50 addresses from the LAN subnet's first, or every address in it if that is fewer) |
| `--scope <cidr>,<pool>/<count>,<router>[,<dns>]` | a subnet behind a BOOTP relay agent, repeatable, one per subnet; `--pool` and the LAN interface still answer the requests this host hears directly |
| `--lease <min>` | lease length in minutes (default 1440) |
| `--udp-timeout <sec>` | how long an idle UDP mapping lives (default 300, floor 120) |
| `--dns <ipv4>` | upstream resolver (default: the one configured on the WAN interface) |
| `--no-dhcp` / `--no-dns` | leave out either listener; the NAT does not need them |
| `--trace <count>` | two sniff-only handles: the forward layer, printing what the main handle is offered, and the network layer's inbound path, printing only the LAN subnet's packets and the answers to mapped ports (60 lines on each if `<count>` is omitted) |
| `--stats <sec>` | interval for the mapping counters (default 30) |

Both listeners bind the LAN address. The pool answers DISCOVER and REQUEST with this host as option 3
and option 6 and remembers the hostname from option 12; the resolver answers that name from the lease
table without letting the query leave the host, and forwards every other name, caching it for the
shortest TTL among its records. A question the upstream never answers costs its own client the transport
timeout and nobody else: each datagram is answered on its own, and only the cached table is shared.
An answer past the 512 octets RFC 1035 §4.2.1 allows over UDP goes out
cut between whole records, its counts rewritten to what is still there and TC set, and the same port
also listens on TCP, which is where that flag sends a client for the whole answer; the cut is made on
the way out, so the cache keeps every record for the next client. That hostname and the query log are
what a remote device has in place of the PID a local client carries. Neither listener is part of the
forwarding path, and the NAT works with both off.

An answer leaves without the ECH configuration in it: in an HTTPS or SVCB record the `ech` SvcParamKey
(RFC 9848 §3 is where the configuration travels) is rewritten to the private-use 65280 that RFC 9460
§14.3.2 reserves, which §2.4.3 lets a client ignore — the record still parses and the client is handed
nothing to encrypt its ClientHello with. The cache stores the rewritten message, and the two answers that never
pass through this resolver — the host's own, on the reply leg, and a LAN client's to a server it named itself,
on the forwarding leg — get the same rewrite in place; no length changes, so only the checksums are redone. A
DoT or DoH answer is not reached, nor is a TCP answer split across segments, and a client that already holds a
configuration keeps it until its TTL runs out.

A client's request has to reach those listeners, and Windows filters inbound, so each port that bound is
asked with one UDP datagram from inside the LAN subnet before the forwarding path opens. For UDP the
listener is the whole witness: a datagram the filter lets through is delivered, so the arrival count
answers it — where the relay's TCP probe had to be read out of the connection table instead. The
resolver's TCP port is asked the same way the relay's was, with one SYN whose arrival is a `SYN-RECEIVED`
row (RFC 9293 §3.5: a lone SYN never reaches an accept queue), and that verdict only reports: a device
that never sees a truncated answer never opens the connection, so the run goes on. A UDP port that heard
nothing ends the run rather than waiting for a device that cannot get a lease, and the rule store is
not consulted for either verdict. `--allow-lan-in` puts `router-lan-in` (UDP) and `router-dns-tcp-in`
(TCP 53) in the store for the listeners this run started and takes each back out when the run ends.

```powershell
New-NetFirewallRule -DisplayName 'router-lan-in' -Direction Inbound -Protocol UDP -LocalPort 53,67 -Action Allow -Profile Any
New-NetFirewallRule -DisplayName 'router-dns-tcp-in' -Direction Inbound -Protocol TCP -LocalPort 53 -Action Allow -Profile Any
```

A request that arrives through a BOOTP relay agent carries the agent's address in `giaddr`, and it is
answered from the `--scope` whose CIDR contains that address — its pool, its options 1, 3, 6, 28, 51 and
54 — with the reply sent to UDP port 67 on the agent instead of to the client, because RFC 2131 §4.1 says
a server that sees a nonzero `giaddr` sends any return message to the 'DHCP server' port on the relay
agent named there. `giaddr` zero keeps answering from `--pool` and the LAN interface, as before. A
`giaddr` in no `--scope` is left unanswered and printed. The agent itself has to be configured to forward
to this host's LAN address on port 67; relaying a client's broadcast is the agent's job, not this
program's.

The capture point is WinDivert's forward layer, which the driver's documentation defines as packets the
machine routes rather than delivers to or from itself; the network layer the proxy sits on is never offered
one. At this layer the packet is already past the routing decision, and `IfIdx` is documented as the
interface an outbound packet is to be sent on, so the reinjection goes back with the address it arrived
with and the rewrite changes only bytes inside the packet. Direction therefore comes from the packet's own
addresses and never from an interface index — the reply is matched on the mapped port alone, before any
interface condition, because an answer may come back by another route than the query left by (RFC 4787
REQ-1). Judging a fix here: the driver documents that injecting certain inbound ICMP messages fails, so a
`rewritefail` that moves only while pinging is not evidence about the NAT, and a TCP or UDP flow is the
shape to judge first.

The LAN device's gateway has to be this interface's address. Per-interface IPv4 forwarding
(`Set-NetIPInterface -Forwarding Enabled`) is what puts a client's packet on
that layer at all, so without it the program prints the two commands and stops rather than black-holing
traffic; `--enable-forwarding` does it and is reversible. Windows' own NAT owns the same path, so a running
`SharedAccess` is refused at startup and `--stop-ics` stops it for the run. Priority orders the
handles within one layer, not across layers: a forwarded flow reaches the proxy only when it runs with
`--lan` and the flow's source is inside that subnet, and at the same layer the proxy's 0 is asked
before Router's -100. Router still sees what the proxy passes through, because a bypass is the packet
reinjected without the impostor bit, not a drop.

The two legs are taken at two layers, because the stack classifies them differently. The outbound leg is
forwarding, so it is diverted at the forward layer. A reply is addressed to this host's own WAN address,
which is local delivery rather than forwarding, so it is diverted at the network layer — with the filter
bounded to that address and to the mapped port range, because an unbounded inbound handle at that layer
would take every packet this machine receives. Both legs hand the packet to the same `Translate`; the
rewritten reply is put back marked impostor, which is what stops the forward handle from taking it again on
its way to the client and makes the driver decrement the TTL. Because that handle also captures this host's
own high-port inbound traffic, stopping has to be unconditional: `Ctrl+C` shuts the handles down from the
interrupt handler — the only thing that releases a thread blocked in `WinDivertRecv` — and the process exits
on its own if that has not finished 3 s later, so a diverted packet is never left stranded.

Each side is chosen from exactly one candidate or not at all, and a refusal lists the candidates with their
media type. `--wan` is there because more than one interface can carry a default gateway, and enumeration
order cannot know which one a client should leave through. The
LAN side is one interface: if `--lan` names an address that more than one connected interface carries the
program refuses instead of picking one, and a LAN-sourced off-link packet whose egress is not the configured
WAN interface is counted as `wrongif` in the `--stats` line rather than dropped in silence. Every other path
— the two listeners, and a reply addressed to the WAN address itself — works with a wrong WAN index, so that
counter is the only thing that says the index is wrong. A diverted packet has already left the stack, so a
reinjection that fails loses it outright; `passthroughfail` and `rewritefail` count the two call sites on each
leg, and the first failure of each prints the driver's error. `--stats` prints the forwarding leg's counters
and, on the line below, the reply leg's own `recv`/`passthroughfail`/`rewritefail`.

The WAN address is re-read on the same five-second sweep that expires mappings, because a renewed lease
changes two things at once: the source a SNAT writes, and the address the reply leg's filter names. The
sweep moves the table and re-opens the leg as one step, printing the old and new addresses; a leg that
cannot be re-opened leaves both where they were, because a table on the new address with a filter on the
old sends packets out and never takes their answers back — harder to read than one stale address.

The mapping is endpoint-independent (RFC 4787 REQ-1): it is keyed on the client's address and port
alone, and an inbound packet is matched on the mapped port alone, so any external host may send back to
a mapping the LAN side opened. A mapped port keeps the internal port's parity (REQ-4), and two
allocations of opposite parity taken back to back land on adjacent ports. TCP and ICMP sit at their RFC
floors (2 h 4 min and 4 min; 60 s); only UDP is tunable, and `--udp-timeout` refuses below the 120 s
floor REQ-5 sets.

Every fragment of a datagram follows the first one's rewrite (RFC 4787 §11 REQ-14), keyed on the
protocol, the two addresses and the datagram id the far host reassembles on; a fragment whose first one
never came this way is forwarded as it arrived; `frag` counts the second case, `fragmap` the first. The
transport checksum a rewrite invalidates is folded from the changed words (RFC 1624 §2), because the rest
of the datagram is not on hand to recompute it from. ICMP errors are translated for both realms and
refresh no query's timer (RFC 5508 REQ-4/5/6); one whose quoted header does not validate or names no
mapping of ours is dropped with the reason printed, counted as `icmperr` and `icmpdrop`.

`--trace` sniffs two layers at once, both above the main handle in priority. `[Trace fwd]` is what the main
handle is offered — never the reinjection, because a packet a handle injects is offered only to the handles
below it. `[Trace net]` prints only the LAN subnet's packets and the answers to mapped ports, because every
inbound packet this host is sent also passes through that layer. Measured on a live run, the forward-layer
window held no inbound packet at all while the network layer showed the answers arriving at the WAN address:
a reply to a SNATed client is addressed to this host, so it is local delivery rather than forwarding, and
`dnat=0` on that capture point is a layer fact, which is why the reply leg below exists. `tools\inject --fwd`
watches the forward layer from outside a
running Router.

`tools\inject` writes a packet shaped like a leased client's, injects it inbound on an interface named by
number with `Impostor` clear so a filter asking for `not impostor` takes it, and reads the network layer
from above and from below its own injection:

```powershell
tools\inject\bin\Debug\net10.0-windows\inject.exe --dst 223.5.5.5 --ifidx 5 --count 3 --watch 8
```

`--count 0` injects nothing and leaves the readers running, which is how a real client's own packet gets
watched; an injected packet is offered only to handles below the one that sent it, so injection is not a
substitute for a client. `--subifidx` is read from a packet that really arrived during `--calibrate` unless
given. `--any` prints every packet on `--ifidx` in either direction and ends with a tally of where `--src`
sent and who answered it. `--filter` replaces the default `tcp or udp or icmp` on every handle; an IPv6
expression such as `--filter "ipv6 and icmpv6"` makes the readers print each IPv6 packet's addresses and
ICMPv6 type — NS and NA with the target they name — outside the IPv4 tallies. `--fwd` puts two readers on
the forward layer, one above Router's priority and one
below it: the first is offered the client's packet as Router is, the second sees whatever Router puts back,
and each ends with the address shapes it counted. The last lines say which of the outcomes happened — the
request never reached the forwarding path, reached it and nothing came back below Router, came back with a
source that is not the client's, or came back with the client's address still in it — and the network-layer
readers answer only the question in front of those, whether the client's packets reach this host at all.

## Tests

```powershell
tests\run-offline.ps1
```

No admin and no WinDivert: the real `MitmProxy` is driven through `FakeRedirector`, so each mode is
a loopback conversation the harness judges itself. Stop a live `TlsMitm` first — it intercepts the
suite's own loopback traffic and turns passing modes into false failures.

* `starttlsprobe` — 37 modes, run as four grouped processes: STARTTLS for SMTP/IMAP/POP3/FTP/NNTP and the
  two element dialects, LDAP's BER and XMPP's XML, each with its split-write, refusal and unreadable-stream
  cases, XMPP's nameless-hello leaf verdict, FTPS passive/active/clear, ALPN, IPv6, implicit TLS without
  SNI, emSign and per-process chains, 0-RTT, the ECH hello terminated and relayed blind, close_notify
  via a strict Schannel client, a Node client that refuses the flight and must leave its handshake in an
  `*_aborted.pcap`, an upstream that refuses the composed hello and must leave the session to a blind
  relay, the process-scope decision table, and `rootcheck`, which
  compares the root the suite signs with against the one `RootCa` finds on its own and checks that
  `--init-ca` produces the same shape. The emSign modes use Electron when `TLSMITM_ELECTRON` or the
  default Qoder install is available, then fall back to Node; `TLSMITM_NODE` overrides the Node
  executable.
  The chain the client is *presented* must name an emSign intermediate and the relay must complete;
  whether its own store trusts the legacy eMSign roots is recorded, not required. A single mode still
  runs on its own: `starttlsprobe.exe smtp`.
* `echcheck` — the `EchDowngrade` state machine (probe, data proof, failed-leg fallback, independent
  hosts) on an injected clock, so the 10-minute window is stepped over rather than waited out.
* `natcheck` — the router's rewrite on synthetic packets: both NAT directions, endpoint-independent
  mapping (RFC 4787 REQ-1), port parity (REQ-4), what must stay out of the table, and the mapping
  timeouts — the UDP one configurable, with REQ-5's two-minute floor enforced rather than rounded to.
  It covers a WAN lease renew too: the table moves to the new address with every mapping intact, and an
  error quoting a datagram sent under the old address is dropped rather than translated.
  It references `Router.csproj`, so the core is tested without a driver, without admin and without a
  second interface.
* `servcheck` — the router's DHCP pool and resolver: DISCOVER/OFFER/REQUEST/ACK, the two NAK cases,
  option 61 as the client's identity, the broadcast-flag rule for the reply's destination, the relayed
  half (`giaddr` matched to a scope, the reply to `giaddr:67`, a scope's options 1/3/6/28/51/54, an
  unmatched `giaddr` unanswered) and every way `--scope` can be written wrong, DECLINE reserving and
  RELEASE freeing an address, lease expiry on an injected clock; and for DNS, refusal of malformed
  questions, the client's own transaction id on a forwarded answer, the TTL that bounds the cache, and
  the TCP retry a truncated UDP answer calls for. On the client's side it pins the cut an over-ceiling
  answer goes out as — between whole records, every section's count rewritten to what is still in the
  bytes, TC set, and the question untouched — and the two-octet length RFC 1035 §4.2.2 puts in front of
  the message on the TCP leg. A question the upstream leaves hanging is answered on its own in both the
  resolver and the listener's receive loop, and a loopback socket is what pins the second half; the
  transport itself is injected, so no resolver is asked. The ECH neutralisation is pinned at both levels
  it runs at: the record's key becomes the private-use one and nothing else moves, alpn beside it is
  untouched, a malformed length is left alone, a second pass finds nothing; and inside a UDP datagram and
  a TCP segment the same rewrite is found by source port 53 and a whole message, with a fragment, a
  partial segment and a query going the other way left as they were.
* `no-sni-test.ps1` — the ClientHello parser and the leaf SAN type, by reflection (needs `pwsh`;
  Windows PowerShell cannot reflect over a net10.0 assembly).

`tests/chainprobe` serves our real chains on loopback to strict clients and records the verdicts; its
README has the modes.
`tools/` holds the remaining manual probes: `ftps-upstream-probe.ps1`, `probe.ps1`,
`read-proc-env.ps1`, and `tools\apcheck`, which prints what the wireless driver reports about hosted
networks and the current hosted-network state — queries only, so it needs no elevation and changes nothing.

## Layout

```
TlsMitm/             the proxy (Program, MitmProxy, redirector, cert engines, relay legs)
  openssl/           embedded libssl/libcrypto (Apache-2.0)
  windivert/         embedded WinDivert 2.2.2: DLL + kernel driver (LGPL-3.0)
  emsign_certs/      intermediates + cross-signed chain used for Node/Electron clients
Router/              the standalone NAT router (NAT core, DHCP pool, resolver, interface discovery)
tests/               offline suites (run-offline.ps1) and the live chainprobe
tools/               manual probes
```

## Licensing

The proxy is Apache-2.0; see `LICENSE`. Two third-party binaries are redistributed with it:

* **WinDivert 2.2.2** — LGPL-3.0, or GPL-2.0 at your option (`TlsMitm/windivert/COPYING`,
  `COPYING.LESSER`). The DLL and driver are unpacked from embedded resources into `%APPDATA%`, so a
  replacement build can be dropped in place.
* **OpenSSL 3.x** — Apache-2.0 (`TlsMitm/openssl/LICENSE.txt`); the DLL pair is unpacked the same way.

## Caveats

* It affects **all** outbound TCP while running, including the app you started it from.
* A client that ignores the Windows store and uses its own bundle (for example a Python build
  reading `certifi`, or a Go program with its own `x509.CertPool`) will reject the leaf; that is
  trust, not interception failure.
* Use only on hosts and traffic you are authorised to inspect.
