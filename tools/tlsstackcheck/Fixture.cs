using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// The certificate the proxy hands its SChannel legs, built the same way: a PFX round trip with a
/// persisted key. The ephemeral form is kept beside it so a knob probe can show what the stack does with
/// it instead of leaving the PFX dance unexplained. Nothing is installed anywhere, and the trust decision
/// on the other leg is a callback that returns true.
/// </summary>
internal sealed class Fixture : IDisposable
{
    public X509Certificate2 Leaf { get; }
    public X509Certificate2 Ephemeral { get; }
    private readonly RSA _key;

    public Fixture()
    {
        _key = RSA.Create(2048);
        Leaf = Load(Made(_key), X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
        Ephemeral = Load(Made(_key), X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
    }

    private static X509Certificate2 Load(X509Certificate2 made, X509KeyStorageFlags flags) =>
        X509CertificateLoader.LoadPkcs12(made.Export(X509ContentType.Pfx, ""), "", flags);

    private static X509Certificate2 Made(RSA key)
    {
        var request = new CertificateRequest("CN=probe.example", key, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("probe.example");
        request.CertificateExtensions.Add(san.Build());
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddMinutes(10));
    }

    public void Dispose()
    {
        Leaf.Dispose();
        Ephemeral.Dispose();
        _key.Dispose();
    }
}
