// Strict verifier, standing in for real clients: Node uses its bundled Mozilla store, does no
// AIA fetching, and here trusts ONLY the probe root - so it passes only if the server actually
// sent the intermediate on the wire.
const tls = require('tls');
const fs = require('fs');
const path = require('path');

const outDir = path.join(__dirname, 'bin', 'Debug', 'net10.0', 'out');
const port = parseInt(process.argv[2], 10);

const sock = tls.connect({
  host: '127.0.0.1',
  port,
  servername: 'probe.example',
  ca: fs.readFileSync(path.join(outDir, 'root.pem')),
  rejectUnauthorized: true,
}, () => {
  console.log(`NODE: handshake OK authorized=${sock.authorized} tlsVersion=${sock.getProtocol()} certCount=${(sock.getPeerCertificate(true).subjectCertificate||'').length}`);
  let c = sock.getPeerCertificate(true), depth = 0;
  const seen = new Set();
  while (c && !seen.has(c.fingerprint256) && depth < 8) {
    seen.add(c.fingerprint256);
    console.log(`  [${depth}] ${JSON.stringify(c.subject)} <- ${JSON.stringify(c.issuer)}`);
    c = c.issuerCertificate;
    depth++;
  }
  process.exit(0);
});
sock.on('error', (e) => { console.log(`NODE: REJECTED ${e.code} ${e.message}`); process.exit(1); });
setTimeout(() => { console.log('NODE: timeout'); process.exit(2); }, 15000);
