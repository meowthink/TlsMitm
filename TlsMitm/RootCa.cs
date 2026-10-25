using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TlsMitm;

public static class RootCa
{
    // Fiddler regenerates its root on every reinstall but keeps the subject name, so the store ends
    // up holding several DO_NOT_TRUST_FiddlerRoot certificates with different keys. Picking the
    // first match made the signing root vary between runs, so selection has to be an explicit rule.
    private const string RootSubjectCn = "DO_NOT_TRUST_FiddlerRoot";
    private const string RootSubject =
        "CN=DO_NOT_TRUST_FiddlerRoot, O=DO_NOT_TRUST, OU=Created by http://www.fiddler2.com";

    public static X509Certificate2 GetFiddlerRoot()
    {
        var found = TryFind();
        if (found != null) return found;
        throw new InvalidOperationException(
            "No usable root certificate found. Run elevated with --init-ca to create one, " +
            "or pass --root <pfx> for a root this process can read.");
    }

    /// <summary>
    /// Finds a root that can sign, across the stores a root may legitimately live in. Both locations
    /// and both stores matter: the trust anchor sits in <c>Root</c> while the signing context sits in
    /// <c>My</c>, and a service (or a machine-wide install from --init-ca) has no CurrentUser copy at
    /// all. Copies are grouped by thumbprint first, because a Root copy carries no key and would
    /// otherwise hide the My copy that does.
    /// </summary>
    public static X509Certificate2? TryFind()
    {
        var copies = new Dictionary<string, List<X509Certificate2>>(StringComparer.OrdinalIgnoreCase);
        var named = 0;
        foreach (var location in new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
        {
            foreach (var name in new[] { StoreName.Root, StoreName.My })
            {
                using var store = new X509Store(name, location);
                store.Open(OpenFlags.ReadOnly);
                var found = store.Certificates.Find(X509FindType.FindBySubjectName, RootSubjectCn, validOnly: false);
                named += found.Count;
                foreach (var cert in found.Cast<X509Certificate2>())
                {
                    if (!copies.TryGetValue(cert.Thumbprint, out var list))
                        copies[cert.Thumbprint] = list = new List<X509Certificate2>();
                    list.Add(cert);
                }
            }
        }

        var usable = new List<X509Certificate2>();
        foreach (var (_, list) in copies)
        {
            // HasPrivateKey only reports a key *reference*; a stale entry can point at a key that is
            // gone or not ours to use. The only honest test is to sign with it.
            var signer = list.FirstOrDefault(CanSign);
            if (signer != null) usable.Add(signer);
        }

        var machineWide = LoadMachineWideThumbprints();

        Console.WriteLine($"[RootCa] {named} certs named {RootSubjectCn} (copies: {copies.Count}), " +
            $"{usable.Count} with a usable key");
        foreach (var cert in usable)
            Console.WriteLine($"[RootCa]   candidate {cert.Thumbprint}  {cert.NotBefore:yyyy-MM-dd HH:mm:ss}..{cert.NotAfter:yyyy-MM-dd HH:mm:ss}"
                + (machineWide.Contains(cert.Thumbprint) ? "  machine-wide" : ""));

        if (usable.Count == 0) return null;

        // Fiddler regenerates its root within seconds of a reinstall dance, so same-day roots with
        // identical validity are normal and a date sort would be a coin flip. The one that reached
        // LocalMachine\Root is the one "Trust Me!" settled on, so it is the real root and the rest
        // are orphans.
        var chosen = usable
            .OrderByDescending(c => machineWide.Contains(c.Thumbprint))
            .ThenByDescending(c => c.NotAfter)
            .ThenBy(c => c.Thumbprint, StringComparer.Ordinal)
            .First();

        if (usable.Count > 1)
            Console.WriteLine($"[RootCa] Warning: {usable.Count} usable roots share this subject; trusting the disambiguation rules above");

        Console.WriteLine($"[RootCa] Using root {chosen.Thumbprint} (CN={RootSubjectCn})");
        return chosen;
    }

    /// <summary>A root supplied by the operator, rather than discovered in a store.</summary>
    public static X509Certificate2 LoadFromPfx(string path, string? password)
    {
        var cert = X509CertificateLoader.LoadPkcs12FromFile(path, password ?? "",
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
        return RequireSigningRoot(cert, path);
    }

    public static X509Certificate2 FindByThumbprint(string thumbprint)
    {
        foreach (var location in new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
        {
            foreach (var name in new[] { StoreName.My, StoreName.Root })
            {
                using var store = new X509Store(name, location);
                store.Open(OpenFlags.ReadOnly);
                var found = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
                foreach (var cert in found.Cast<X509Certificate2>())
                    if (CanSign(cert)) return cert;
            }
        }
        throw new InvalidOperationException(
            $"No certificate with thumbprint {thumbprint} is installed with a usable private key");
    }

    /// <summary>
    /// Creates the root this tool signs with when the machine has none (no Fiddler, a clean runner, a
    /// service account). Machine-wide, because a root in one user's profile cannot serve a service or
    /// a second user, and because LocalMachine store writes take no interactive consent dialog.
    /// </summary>
    public static X509Certificate2 CreateAndInstall()
    {
        var existing = TryFind();
        if (existing != null)
        {
            Console.WriteLine($"[RootCa] A usable root is already installed ({existing.Thumbprint}); not creating another");
            return existing;
        }

        var cert = CreateRootCertificate();
        try
        {
            var pfx = cert.Export(X509ContentType.Pfx, "");
            // MachineKeySet keeps the key in the machine profile (where a service can read it) and
            // PersistKeySet keeps it after this process' handle closes, which is what RootCa tests.
            var persisted = X509CertificateLoader.LoadPkcs12(pfx, "", X509KeyStorageFlags.MachineKeySet
                | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
            try
            {
                AddToStore(StoreName.My, persisted);
            }
            finally
            {
                persisted.Dispose();
            }

            using var anchor = X509CertificateLoader.LoadCertificate(cert.RawData);
            AddToStore(StoreName.Root, anchor);
        }
        finally
        {
            cert.Dispose();
        }

        var installed = TryFind();
        if (installed == null)
            throw new InvalidOperationException(
                "The root was written to LocalMachine\\My and LocalMachine\\Root but no usable copy is discoverable");
        Console.WriteLine($"[RootCa] Installed root {installed.Thumbprint} (machine-wide)");
        return installed;
    }

    private static void AddToStore(StoreName name, X509Certificate2 cert)
    {
        try
        {
            using var store = new X509Store(name, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);
            store.Add(cert);
        }
        catch (Exception ex) when (ex is CryptographicException or UnauthorizedAccessException)
        {
            throw new InvalidOperationException(
                $"--init-ca writes LocalMachine\\{name} and must run elevated: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// The shape the root has to have to certify leaves: CA=TRUE with pathLen 0, keyCertSign|cRLSign,
    /// serverAuth EKU - the same shape as the Fiddler root measured on a Fiddler machine.
    /// </summary>
    public static X509Certificate2 CreateRootCertificate()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(RootSubject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        var eku = new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") };
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, false));
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(820));
    }

    private static X509Certificate2 RequireSigningRoot(X509Certificate2 cert, string source)
    {
        var basic = cert.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
        if (basic is not { CertificateAuthority: true })
            throw new InvalidOperationException($"{source} is not a CA certificate (basicConstraints cA is not TRUE)");
        if (!CanSign(cert))
            throw new InvalidOperationException($"{source} has no private key this process can sign with");
        return cert;
    }

    private static HashSet<string> LoadMachineWideThumbprints()
    {
        using var machine = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        machine.Open(OpenFlags.ReadOnly);
        return machine.Certificates
            .Find(X509FindType.FindBySubjectName, RootSubjectCn, validOnly: false)
            .Cast<X509Certificate2>()
            .Select(c => c.Thumbprint)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    private static bool CanSign(X509Certificate2 cert)
    {
        try
        {
            using var rsa = cert.GetRSAPrivateKey();
            if (rsa == null) return false;
            rsa.SignData(new byte[4], HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}
