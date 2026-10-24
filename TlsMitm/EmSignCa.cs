using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TlsMitm;

public class EmSignCa
{
    public string Name { get; }
    public int ScalarValue { get; }
    public X509Certificate2 CertificateWithKey { get; }

    // Verifiers only hold the trust anchor locally; the intermediate and the cross-signed root have
    // to be sent or the path cannot be built. RFC 9846 §4.5.1 puts the sender's certificate first as a
    // MUST and each certificate certifying the one before it as a SHOULD, and lets the anchor itself be
    // omitted because a peer that can validate the chain must already hold it.
    public X509Certificate2Collection? ChainCertificates { get; }

    private EmSignCa(string name, int scalarValue, X509Certificate2 certWithKey, X509Certificate2Collection? chain)
    {
        Name = name;
        ScalarValue = scalarValue;
        CertificateWithKey = certWithKey;
        ChainCertificates = chain;
    }

    public static EmSignCa LoadFromPem(string name, int scalarValue, string pemPath, IEnumerable<string>? chainPaths = null)
    {
        var cert = X509CertificateLoader.LoadCertificate(File.ReadAllBytes(pemPath));

        X509Certificate2Collection? chain = null;
        if (chainPaths != null)
        {
            var collected = new X509Certificate2Collection();
            foreach (var path in chainPaths)
            {
                if (string.Equals(path, pemPath, StringComparison.OrdinalIgnoreCase)) continue;
                collected.Add(X509CertificateLoader.LoadCertificate(File.ReadAllBytes(path)));
            }
            if (collected.Count > 0) chain = OrderChain(cert.Issuer, collected);
        }

        return LoadFromCertificate(name, scalarValue, cert, chain);
    }

    public static EmSignCa LoadFromCertificate(
        string name, int scalarValue, X509Certificate2 certificate, X509Certificate2Collection? chain = null)
    {
        var ecdsaPub = certificate.GetECDsaPublicKey();
        if (ecdsaPub == null)
            throw new InvalidOperationException($"Certificate {name} does not have an ECDSA public key");

        var pubParams = ecdsaPub.ExportParameters(false);

        var scalarBytes = ScalarToBytes(scalarValue, 48);

        var keyParams = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP384,
            D = scalarBytes,
            Q = pubParams.Q
        };

        var ecdsa = ECDsa.Create(keyParams);
        var certWithKey = certificate.CopyWithPrivateKey(ecdsa);

        Console.WriteLine($"[EmSignCa] Loaded {name} with scalar {scalarValue}" +
            (chain == null ? "" : $", {chain.Count} chain certs attached"));
        return new EmSignCa(name, scalarValue, certWithKey, chain);
    }

    // RFC 9846 §4.5.1: everything goes in the one certificate_list of the Certificate message, and "the
    // sender's certificate MUST come in the first CertificateEntry in the list", each following entry
    // SHOULD certify the one before it. libssl sends extra chain certificates in the order they were
    // added, and directory order put the self-signed anchor before the cross.
    private static X509Certificate2Collection OrderChain(string issuer, X509Certificate2Collection certs)
    {
        var ordered = new X509Certificate2Collection();
        var remaining = new List<X509Certificate2>(certs);
        var current = issuer;
        while (remaining.Count > 0)
        {
            var next = remaining.FirstOrDefault(c => c.Subject == current) ?? remaining[0];
            ordered.Add(next);
            remaining.Remove(next);
            if (next.Subject == next.Issuer) break;
            current = next.Issuer;
        }
        return ordered;
    }

    private static byte[] ScalarToBytes(int scalar, int length)
    {
        var bytes = new byte[length];
        var scalarBytes = BitConverter.GetBytes(scalar);

        if (BitConverter.IsLittleEndian)
            Array.Reverse(scalarBytes);

        Array.Copy(scalarBytes, 0, bytes, length - scalarBytes.Length, scalarBytes.Length);
        return bytes;
    }

    public static readonly (string Name, int Scalar)[] KnownIntermediates = new[]
    {
        ("EM DV TLS CA - G3B", 156),
        ("EM DV TLS CA - G3C", 230),
        ("EM EV TLS CA - G3B", 115),
        ("EM EV TLS CA - G3C", 56),
        ("EM OV TLS CA - G3B", 155),
        ("EM OV TLS CA - G3C", 4),
        ("EM OV CS CA - G3B", 66),
        ("EM OV CS CA - G3C", 237)
    };
}
