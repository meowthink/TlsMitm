using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TlsMitm;

// Offline judgement for leaf issuance: an in-memory root (nothing is installed in any store), and the
// shapes a strict verifier checks - the SAN type per reference identifier (RFC 9525 §6.2: a domain is a
// dNSName, an IP literal an iPAddress), the wildcard's base-domain coverage, the CA/Browser Forum validity
// ceiling, the leaf-not-CA constraints, and that the leaf actually chains to the root. Chain trust itself
// is chainprobe's subject; here it is only that issuance produces a verifiable leaf.
var failures = new List<string>();
void Expect(bool ok, string what)
{
    if (!ok) failures.Add(what);
    Console.WriteLine($"{(ok ? "ok  " : "FAIL")} {what}");
}

using var rootKey = RSA.Create(2048);
var rootReq = new CertificateRequest("CN=CertCheck Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
using var root = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(3650));

var engine = new CertEngine(root, null, CertEngineMode.FiddlerOnly, null);

static X509SubjectAlternativeNameExtension? San(X509Certificate2 c) =>
    (X509SubjectAlternativeNameExtension?)c.Extensions["2.5.29.17"];

// --- a domain leaf -----------------------------------------------------------------------------------
var leaf = engine.GetCert("www.example.com").Leaf;
Expect(leaf.Issuer == root.Subject, "the leaf is issued by the root");
Expect(leaf.Subject == "CN=www.example.com", "the leaf CN is the hostname");
var san = San(leaf);
Expect(san != null && san.EnumerateDnsNames().Contains("www.example.com"), "the SAN carries the DNS name");
Expect(san != null && !san.EnumerateIPAddresses().Any(), "a domain leaf carries no IP SAN");
var span = leaf.NotAfter - leaf.NotBefore;
Expect(span.TotalDays <= 398 && span.TotalDays >= 1, $"the leaf validity is under the 398-day ceiling, got {span.TotalDays:0} days");
var ku = (X509KeyUsageExtension?)leaf.Extensions["2.5.29.15"];
Expect(ku != null && ku.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature) && !ku.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign),
    "the leaf has server key usage and no keyCertSign");
var bc = (X509BasicConstraintsExtension?)leaf.Extensions["2.5.29.19"];
Expect(bc != null && !bc.CertificateAuthority, "basicConstraints cA is false");

using (var chain = new X509Chain())
{
    chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
    chain.ChainPolicy.CustomTrustStore.Add(root);
    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
    Expect(chain.Build(leaf), "the leaf chains to the root (signature and validity verify)");
}

// --- an IP literal is an iPAddress SAN, not a dNSName ------------------------------------------------
var ipLeaf = engine.GetCert("192.0.2.1").Leaf;
var ipSan = San(ipLeaf);
Expect(ipSan != null && ipSan.EnumerateIPAddresses().Contains(IPAddress.Parse("192.0.2.1")),
    "an IP literal gets an iPAddress SAN");
Expect(ipSan != null && !ipSan.EnumerateDnsNames().Contains("192.0.2.1"), "an IP literal is not a DNS SAN");

// --- a wildcard also covers the base domain ----------------------------------------------------------
var wild = engine.GetCert("*.example.com").Leaf;
var wildSan = San(wild);
Expect(wildSan != null && wildSan.EnumerateDnsNames().Contains("*.example.com"), "the wildcard SAN is present");
Expect(wildSan != null && wildSan.EnumerateDnsNames().Contains("example.com"), "the wildcard also covers the base domain");

// --- caching and a long label ------------------------------------------------------------------------
var again = engine.GetCert("www.example.com").Leaf;
Expect(again.SerialNumber == leaf.SerialNumber, "the same hostname is cached, not re-minted");
var longLeaf = engine.GetCert(new string('a', 63) + ".example.com").Leaf;
Expect(San(longLeaf) != null, "a 63-octet label issues a leaf");

if (failures.Count > 0)
{
    Console.WriteLine($"[certcheck] FAIL ({failures.Count})");
    return 1;
}
Console.WriteLine("[certcheck] PASS - SAN types, wildcard coverage, validity ceiling, leaf constraints, chain to root, caching");
return 0;
