using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TlsMitm;

public enum CertEngineMode
{
    FiddlerOnly,      // Fiddler root certificate only
    EmSignOnly,       // emSign intermediate certificates only
    Rotate,            // Rotate between all CAs
    Auto               // Per client: emSign for Node/Electron, Fiddler for everything else
}

// The chain, when present, is the only way the intermediate and cross-signed root reach the client:
// SChannel builds a credential's chain from the local stores, which do not contain these CAs, so the
// client leg is served by libssl and sent exactly this collection. RFC 9846 §4.5.1 fixes the order the
// wire list follows - the sender's certificate MUST come first, each following certificate SHOULD
// directly certify the one before it - and a trust anchor MAY be omitted, since a peer able to
// validate the chain must already hold it. The same section notes that verifiers have to tolerate other
// orderings, so this is what we send rather than what a peer may demand.
public readonly record struct IssuedCert(X509Certificate2 Leaf, X509Certificate2Collection? Chain);

public class CertEngine
{
    private sealed class SigningAuthority
    {
        public required X509Certificate2 Certificate { get; init; }
        public X509Certificate2Collection? Chain { get; init; }
    }

    private readonly X509Certificate2 _fiddlerRoot;
    private readonly List<EmSignCa> _emSignCas;
    private readonly CertEngineMode _mode;
    private readonly CrlService? _crl;
    // Lazy turns a duplicate factory run into a shared one: GetOrAdd is allowed to run its factory for
    // the same key concurrently, and each extra run would generate an RSA key nobody keeps.
    private readonly ConcurrentDictionary<string, Lazy<IssuedCert>> _cache = new(StringComparer.OrdinalIgnoreCase);
    private int _nextCaIndex;

    public CertEngine(X509Certificate2 fiddlerRoot, List<EmSignCa>? emSignCas = null,
        CertEngineMode mode = CertEngineMode.FiddlerOnly, CrlService? crl = null)
    {
        _fiddlerRoot = fiddlerRoot;
        _emSignCas = emSignCas ?? new();
        _mode = mode;
        _crl = crl;

        if ((_mode is CertEngineMode.EmSignOnly or CertEngineMode.Auto) && _emSignCas.Count == 0)
        {
            Console.WriteLine("[CertEngine] Warning: emSign mode requested but no emSign certs loaded, falling back to Fiddler");
            _mode = CertEngineMode.FiddlerOnly;
        }

        Console.WriteLine($"[CertEngine] Mode: {_mode}, Fiddler root + {_emSignCas.Count} emSign intermediates");
    }

    /// <summary>
    /// True when the mode actually lets a client's classified trust pick the issuer. Without it the
    /// per-process decision is only a log line and every leaf still comes from the Fiddler root.
    /// </summary>
    public bool HonorsClientTrust =>
        _mode is CertEngineMode.Auto or CertEngineMode.EmSignOnly && _emSignCas.Count > 0;

    public IssuedCert GetCert(string hostname, ClientTrust trust = ClientTrust.WindowsStore)
    {
        // Auto serves two leaf families for the same hostname, so the trust has to be part of the key;
        // the fixed modes never change issuer per client.
        if (_mode != CertEngineMode.Auto)
            return _cache.GetOrAdd(hostname,
                h => new Lazy<IssuedCert>(() => GenerateLeafCert(h, ClientTrust.WindowsStore))).Value;

        var prefix = trust == ClientTrust.NodeBundled && _emSignCas.Count > 0 ? "emsign|" : "fiddler|";
        return _cache.GetOrAdd(prefix + hostname,
            _ => new Lazy<IssuedCert>(() => GenerateLeafCert(hostname, trust))).Value;
    }

    private IssuedCert GenerateLeafCert(string hostname, ClientTrust trust)
    {
        using var rsa = RSA.Create(2048);
        var ca = GetNextSigningCa(trust);
        var req = new CertificateRequest($"CN={hostname}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Leaf, not CA: basicConstraints cA=FALSE, and RFC 5280 §4.2.1.9 then forbids asserting
        // keyCertSign, so keyUsage (§4.2.1.3) carries only the bits a TLS server uses.
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));

        var eku = new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") };
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, false));

        var sanBuilder = new SubjectAlternativeNameBuilder();
        // An address-literal destination arrives here as a dotted string: SNI carries domain names only
        // (RFC 6066 §3; RFC 9525 §7.4), so an IP-dialing client sends no server_name at all. Its
        // reference identifier is an iP-ID, and RFC 9525 §6.2 defines matching for that type solely
        // against iPAddress SAN entries, octet-for-octet (§6.4), where RFC 5280 §4.2.1.6 stores the
        // address as raw network-order bytes. So the SAN has to be added as an iPAddress.
        if (IPAddress.TryParse(hostname, out var ip))
            sanBuilder.AddIpAddress(ip);
        else
            sanBuilder.AddDnsName(hostname);
        if (hostname.Contains('*'))
        {
            var baseDomain = hostname.TrimStart('*', '.');
            sanBuilder.AddDnsName(baseDomain);
        }
        req.CertificateExtensions.Add(sanBuilder.Build());

        // A strict verifier asks "is this revoked?" before it accepts the chain, and whether it fails
        // closed when the answer is unknowable is local policy (RFC 5280 §6.1.3(a)(3) allows CRL,
        // status information or out-of-band mechanisms). Without a pointer Schannel answers
        // CRYPT_E_NO_REVOCATION_CHECK (measured), so cRLDistributionPoints (RFC 5280 §4.2.1.13)
        // points at the loopback CRL and its URI names a single DER-encoded CRL.
        if (_crl != null && _crl.Serves(ca.Certificate))
            req.CertificateExtensions.Add(
                new X509Extension("2.5.29.31", CrlService.DistributionPoints(_crl.Url), false));

        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F; // force a positive serial; the DER encoder treats a leading 0x80 as negative
        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddYears(1);

        notAfter = ClampToIssuer(notAfter, ca.Certificate);
        var cert = CreateSigned(req, ca, serial, notBefore, notAfter);

        if (!cert.HasPrivateKey)
            cert = cert.CopyWithPrivateKey(rsa);

        var pfx = cert.Export(X509ContentType.Pfx, "");
        var leaf = X509CertificateLoader.LoadPkcs12(pfx, "",
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

        // offline: never let chain building reach out to AIA/CRL endpoints; the chain we hand over
        // is exactly the one we ship, and the client's verifier makes the trust decision.
        var chain = ca.Chain == null ? null : ChainWithIssuer(ca);
        return new IssuedCert(leaf, chain);
    }

    private static X509Certificate2Collection ChainWithIssuer(SigningAuthority ca)
    {
        // The intermediate has to be in this collection: it lives in no local store, and without it
        // the offline builder cannot even reach the cross-signed root, yielding an empty chain.
        var chain = new X509Certificate2Collection { ca.Certificate };
        chain.AddRange(ca.Chain!);
        return chain;
    }

    private static X509Certificate2 CreateSigned(
        CertificateRequest req, SigningAuthority ca, byte[] serial, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        // The convenience overload demands issuer and request share a key algorithm, so an ECDSA
        // CA cannot sign an RSA request; route ECDSA issuers through an explicit signature generator.
        using var issuerEcdsa = ca.Certificate.GetECDsaPrivateKey();
        if (issuerEcdsa != null)
        {
            var generator = X509SignatureGenerator.CreateForECDsa(issuerEcdsa);
            return req.Create(ca.Certificate.SubjectName, generator, notBefore, notAfter, serial);
        }
        return req.Create(ca.Certificate, notBefore, notAfter, serial);
    }

    private static DateTimeOffset ClampToIssuer(DateTimeOffset requestedNotAfter, X509Certificate2 issuer)
    {
        // CertificateRequest.Create throws when a leaf outlives its issuer (measured), so an
        // intermediate close to expiry would otherwise fail every signature it is asked to make.
        if (requestedNotAfter <= issuer.NotAfter) return requestedNotAfter;
        return issuer.NotAfter - TimeSpan.FromDays(1);
    }

    private SigningAuthority GetNextSigningCa(ClientTrust trust)
    {
        return _mode switch
        {
            CertEngineMode.FiddlerOnly => new SigningAuthority { Certificate = _fiddlerRoot },
            CertEngineMode.EmSignOnly => GetNextEmSignCa(),
            CertEngineMode.Rotate => GetNextRotatedCa(),
            CertEngineMode.Auto => trust == ClientTrust.NodeBundled && _emSignCas.Count > 0
                ? GetNextEmSignCa()
                : new SigningAuthority { Certificate = _fiddlerRoot },
            _ => new SigningAuthority { Certificate = _fiddlerRoot }
        };
    }

    private SigningAuthority GetNextEmSignCa()
    {
        if (_emSignCas.Count == 0)
            return new SigningAuthority { Certificate = _fiddlerRoot };

        var index = Interlocked.Increment(ref _nextCaIndex) % _emSignCas.Count;
        return FromEmSign(_emSignCas[index]);
    }

    private SigningAuthority GetNextRotatedCa()
    {
        var allCas = new List<SigningAuthority> { new() { Certificate = _fiddlerRoot } };
        allCas.AddRange(_emSignCas.Select(FromEmSign));

        var index = Interlocked.Increment(ref _nextCaIndex) % allCas.Count;
        return allCas[index];
    }

    private static SigningAuthority FromEmSign(EmSignCa ca) => new()
    {
        Certificate = ca.CertificateWithKey,
        Chain = ca.ChainCertificates
    };
}
