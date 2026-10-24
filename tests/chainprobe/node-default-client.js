// Verdict for the emSign plan: connect with Node's DEFAULT trust store (no ca option, no
// NODE_EXTRA_CA_CERTS) and rejectUnauthorized. If this passes, Node's bundled Mozilla roots
// really do anchor leaf -> EM * TLS CA -> emSign Root TLS CA - G3 (cross) -> emSign ECC Root CA - G3.
const tls = require('tls');

const port = parseInt(process.argv[2], 10);
const servername = process.argv[3] || 'emsign-test.example';

console.log(`node ${process.version}: default store has ${tls.getCACertificates('default').length} roots`);

const sock = tls.connect({ host: '127.0.0.1', port, servername, rejectUnauthorized: true }, () => {
  console.log(`NODE: handshake OK authorized=${sock.authorized} protocol=${sock.getProtocol()}`);
  let c = sock.getPeerCertificate(true), depth = 0;
  const seen = new Set();
  while (c && !seen.has(c.fingerprint256) && depth < 8) {
    seen.add(c.fingerprint256);
    console.log(`  [${depth}] ${JSON.stringify(c.subject)} <- ${JSON.stringify(c.issuer)}`);
    c = c.issuerCertificate;
    depth++;
  }
  sock.end();
  process.exit(0);
});
sock.on('error', (e) => { console.log(`NODE: REJECTED ${e.code || ''} ${e.message}`); process.exit(1); });
setTimeout(() => { console.log('NODE: timeout'); process.exit(2); }, 15000);
