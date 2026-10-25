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

1. WinDivert filter `outbound and tcp and not impostor` sees every SYN. The original destination is
   remembered per 4-tuple and the packet is rewritten to the relay port `8443` (addresses swapped,
   so it arrives at the proxy as inbound for the client's own address); the impostor flag keeps the
   rewrite from being captured again.
2. The proxy peeks the first byte on both sockets. `0x16` is implicit TLS. A server-first protocol
   (SMTP/IMAP/POP3/FTP) stays plaintext and is scanned for `STARTTLS` / `STLS` / `AUTH TLS`; after
   the server's readiness reply the same TCP connection is upgraded in place.
3. For TLS the ClientHello is parsed (SNI, ALPN, `early_data`, PSK, ECH, GREASE), the signing chain
   is chosen by the process that owns the client socket, and the session is terminated toward the
   client and re-originated toward the server. A hello the real server refuses is not fatal: the
   client's own hello is replayed on a fresh connection and that session goes blind.
4. ECH hellos are terminated with a leaf for the public name, which is what makes Chromium either
   keep the session or retry without ECH. A host that yields neither application bytes nor a
   plaintext retry within 5 s is relayed blind for 10 minutes, so the site keeps working.
5. 0-RTT and PSK-only resumptions are relayed blind: decryption would need keys we cannot have.
   They are still captured, as is every other TLS session (`captures/<host>_<time>_<id>.pcap`).
   Each file opens with a synthesized three-way handshake, so Wireshark reads one connection from
   its start rather than a fragment out of the middle.
6. QUIC is dropped by long-header signature, so HTTP/3 clients fall back to TCP and stay visible.
7. Every Fiddler-root leaf carries a CRL distribution point served by the proxy itself on
   `http://127.0.0.1:8873/crl/<root-thumbprint>.crl`, so a validating client gets an answer.

## What it decrypts

Detection reads bytes, never ports: a connection whose first byte is `0x16` is implicit TLS whatever
port it uses, and a server-first text protocol is scanned for the upgrade command. The protocol names
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
| XMPP | `<starttls/>` → `<proceed/>` (RFC 6120 §5.4.2) | blind pass-through |
| any other TCP | — | relayed as it comes, not captured |

A grant this proxy does not act on is not a broken session: the two sockets keep carrying bytes, so
client and real server finish the handshake between themselves, and the plaintext simply stays inside
the packets instead of coming out of them. `xmpp` is the offline mode that holds the proxy to that
behaviour; `reject` holds it to a server that really refuses.

## Which chain, for which client

Two roots are usable, and no single chain satisfies both kinds of client:

| client | chain | why |
| --- | --- | --- |
| Windows/SChannel clients (Chromium network service, curl, .NET, svchost) | Fiddler root | they read the Windows store |
| Node, Electron main process, Node-type utilities | emSign intermediate | they only trust their bundled store |

`--emsign` maps the client's ephemeral port to a PID, reads its command line, and picks per
connection; a GREASE-bearing ClientHello from an ambiguous PID is treated as Chromium.

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
* **emSign intermediates** (`TlsMitm/emsign_certs`) are only needed for Node/Electron clients.

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
    [--root <pfx> | --root-thumbprint <thumbprint> | --init-ca]
    [--pid <pid,...> | --exclude-pid <pid,...>]
    [--process <name,...> | --exclude-process <name,...>]
```

| flag | effect |
| --- | --- |
| *(none)* | Fiddler chain for everyone; ECH downgrade on |
| `--emsign` | per-process chain selection (emSign for Node/Electron, Fiddler for the rest) |
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

Scoping is decided at the SYN that starts a flow, so an excluded process is passed through whole —
its packets are never rewritten, rather than half-intercepted. Each pair names a process by pid or by
executable, and an exclusion wins over an include.

The console is mirrored to `tlsmitm-<yyyyMMdd-HHmmss>.log` next to the executable.

## Tests

```powershell
tests\run-offline.ps1
```

No admin and no WinDivert: the real `MitmProxy` is driven through `FakeRedirector`, so each mode is
a loopback conversation the harness judges itself. Stop a live `TlsMitm` first — it intercepts the
suite's own loopback traffic and turns passing modes into false failures.

* `starttlsprobe` — 33 modes, run as four grouped processes: STARTTLS for SMTP/IMAP/POP3/FTP/NNTP/LDAP
  and XMPP's dialect deliberately left alone, FTPS passive/active/clear, ALPN, IPv6, implicit TLS without
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
* `echcheck` — the `EchDowngrade` state machine (probe, proof, blind fallback, independent hosts) on
  an injected clock, so the 5 s window is stepped over rather than waited out.
* `no-sni-test.ps1` — the ClientHello parser and the leaf SAN type, by reflection (needs `pwsh`;
  Windows PowerShell cannot reflect over a net10.0 assembly).

`tests/chainprobe` serves our real chains on loopback to strict clients and records the verdicts; its
README has the modes.
`tools/` holds the remaining manual probes: `ftps-upstream-probe.ps1`, `probe.ps1`,
`read-proc-env.ps1`.

## Layout

```
TlsMitm/             the proxy (Program, MitmProxy, redirector, cert engines, relay legs)
  openssl/           embedded libssl/libcrypto (Apache-2.0)
  windivert/         embedded WinDivert 2.2.2: DLL + kernel driver (LGPL-3.0)
  emsign_certs/      intermediates + cross-signed chain used for Node/Electron clients
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
