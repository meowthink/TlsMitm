using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TlsMitm;

public static class RootCa
{
    // Fiddler regenerates its root on every reinstall but keeps the subject name, so the store ends
    // up holding several DO_NOT_TRUST_FiddlerRoot certificates with different keys. Picking the
    // first match made the signing root vary between runs, so selection has to be an explicit rule.
    private const string RootSubjectCn = "DO_NOT_TRUST_FiddlerRoot";

    public static X509Certificate2 GetFiddlerRoot()
    {
        using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);

        var candidates = store.Certificates
            .Find(X509FindType.FindBySubjectName, RootSubjectCn, validOnly: false)
            .Cast<X509Certificate2>()
            .ToList();

        var usable = new List<X509Certificate2>();
        foreach (var cert in candidates)
        {
            // HasPrivateKey only reports a key *reference*; a stale entry can point at a key that is
            // gone or not ours to use. The only honest test is to sign with it.
            if (!CanSign(cert)) continue;
            usable.Add(cert);
        }

        var machineWide = LoadMachineWideThumbprints();

        Console.WriteLine($"[RootCa] {candidates.Count} certs named {RootSubjectCn}, {usable.Count} with a usable key");
        foreach (var cert in usable)
            Console.WriteLine($"[RootCa]   candidate {cert.Thumbprint}  {cert.NotBefore:yyyy-MM-dd HH:mm:ss}..{cert.NotAfter:yyyy-MM-dd HH:mm:ss}"
                + (machineWide.Contains(cert.Thumbprint) ? "  machine-wide" : ""));

        if (usable.Count == 0)
        {
            throw new InvalidOperationException(
                "Fiddler root certificate not found. Make sure Fiddler has been run with HTTPS decryption enabled.");
        }

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
