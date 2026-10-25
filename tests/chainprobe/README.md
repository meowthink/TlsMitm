# chainprobe

Live checks of the chain the proxy puts on the wire. Everything listens on loopback: no admin, no
trust-store writes, and the clients are strict — they render a verdict instead of accepting.

## Modes

```
chainprobe [gen|plain|context]                         synthetic ECDSA-CA leaf over SslStream
chainprobe client <port>                               Schannel client against one of the servers above
chainprobe emsign <certsDir>                           real emSign leaf over SslStream, one connection
chainprobe emserve <certsDir> <port> [shape] [caIndex] real emSign leaf over the libssl leg
chainprobe fiddler <host> <port> [variant]             real CertEngine Fiddler leaf over SslStream
```

`shape` = `full` | `no-anchor` | `no-intermediate` | `leaf`; `variant` = `plain` | `served` | `cdp` |
`ocsp` | `both` (`served` goes through `CertEngine` + `CrlService`, so it also proves that wiring).
`emserve` is the mode that matches production for an emSign chain: it drives `OpenSslServerStream`,
the same leg MitmProxy uses, and pins one CA via `caIndex` so a wire shape is reproducible per run.
`run-emsign.sh` and `run-matrix.sh` wrap the comparisons that need a server and a client together.

## Measured verdicts (2026-10-25, this host)

Clients: node 24.21.0 (OpenSSL 3.5.8, 121 bundled roots), Electron 37.10.3 (BoringSSL, 146 roots),
and `chainprobe client` (Schannel, Windows store). Leaf subject `emsign-test.example`, TLS 1.3.

| server sends | strict Node / Electron |
|---|---|
| leaf + intermediate + `emSign Root TLS CA - G3` + `emSign ECC Root CA - G3` (our full chain) | `authorized=true` |
| anchor omitted, 3 certs | `authorized=true` |
| signing intermediate omitted | `UNABLE_TO_VERIFY_LEAF_SIGNATURE` |
| leaf only | `UNABLE_TO_VERIFY_LEAF_SIGNATURE` |
| Fiddler leaf over `SslStream` | `UNABLE_TO_VERIFY_LEAF_SIGNATURE` |

The stores the chains anchor in are disjoint: `emSign ECC Root CA - G3` is in every bundled store
above but in neither `CurrentUser\Root` nor `LocalMachine\Root` (those hold only `emSign Root CA - G1`),
and `DO_NOT_TRUST_FiddlerRoot` is in no bundle but is in both Windows stores. So a chain classified
for the wrong client fails, and one host can need both — an Electron main process answers to the
bundled store for Node/undici and to the Windows store for its Chromium network stack.

Other readings from the same runs:

* The Fiddler-leaf row is what establishes Schannel's wire behaviour: it sends the **leaf alone**. Had
  the root been on the wire, the error would name a self-signed certificate instead.
* `node --use-system-ca` + Fiddler leaf → `CERT_SIGNATURE_FAILURE`. `CurrentUser\Root` holds several
  same-subject Fiddler roots, so the client can pair the leaf with the wrong key; this is the hazard
  `TlsMitm/Program.cs:42-45` documents. The same flag + an emSign chain → `authorized=true`, because
  the system store is additive to the bundle.
* Schannel client + the full emSign chain → the chain stops at [leaf, intermediate] with
  `RemoteCertificateChainErrors`; a Windows-store client cannot anchor emSign.
* Every rejecting client produced the same proxy-side line as a client that gave up mid-handshake:
  `IOException: client closed during the handshake`. Counting the client's bytes after its hello does
  not separate the two — measured, a rejecting Node client writes nothing before the EOF. Attribution
  (pid, time, served issuer per connection) is the only way to tell them apart in a live log.
