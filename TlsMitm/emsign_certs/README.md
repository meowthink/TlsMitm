# emSign intermediates

Fallback signing CAs for clients that do not read the Windows certificate store (Node, Electron
main process, Node-based tools). Those clients trust their bundled store, which contains these
intermediates but not the Fiddler root.

```
intermediates/   6 certificates, one per CA
chain/           cross-signed path sent along with a leaf (intermediate -> root)
```

| certificate | CN used for matching | key scalar |
| --- | --- | --- |
| EM-DV-TLS-CA-G3B.crt.pem | `EM DV TLS CA - G3B` | 156 |
| EM-DV-TLS-CA-G3C.crt.pem | `EM DV TLS CA - G3C` | 230 |
| EM-EV-TLS-CA-G3B.crt.pem | `EM EV TLS CA - G3B` | 115 |
| EM-EV-TLS-CA-G3C.crt.pem | `EM EV TLS CA - G3C` | 56 |
| EM-OV-TLS-CA-G3B.crt.pem | `EM OV TLS CA - G3B` | 155 |
| EM-OV-TLS-CA-G3C.crt.pem | `EM OV TLS CA - G3C` | 4 |

The files hold public certificates only. Their P-384 private keys are reconstructed in
`EmSignCa.cs` from the known scalar in `KnownIntermediates`; a certificate is matched by the CN
inside it, never by file name. The two `chain/` files are appended after a leaf in issuer order
(`EmSignCa.OrderChain`) so the peer can build a path to its bundled root.

`KnownIntermediates` also lists the OV code-signing pairs (G3B 66, G3C 237). No certificates are
shipped for them because they sign code, not TLS; the loader skips entries without a file.

These CAs were revoked and removed from trust stores after their keys were found to be
recoverable. They are here so that traffic from applications pinned to their bundled store can be
inspected on machines you are authorised to test.
