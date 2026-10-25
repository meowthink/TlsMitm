# Installs a machine-wide root that looks like the one Fiddler creates, on a machine that has no
# Fiddler root with a usable private key - a disposable CI runner, or an administrator who explicitly
# wants the test fixture. That is the one prerequisite the proxy and the offline suites cannot do
# without, because both sign their leaves with whatever RootCa finds.
#
# The machine stores are deliberate. GitHub's Windows runners block writes to CurrentUser\Root on a
# consent dialog that nobody can answer. The runner is elevated, and LocalMachine store writes do not
# use that dialog. The private key lives in LocalMachine\My; LocalMachine\Root contains only the trust
# anchor.
#
# Mirrors the real one measured on a Fiddler machine: same subject DN, RSA 2048 / sha256RSA,
# basicConstraints CA=TRUE with pathLen 0 (the measured real root is DER 30 06 01 01 FF 02 01 00),
# keyUsage keyCertSign|cRLSign, EKU serverAuth,
# about 820 days of validity, and the private key left in the personal store so the root copy can
# sign - which is what RootCa tests before it accepts a candidate.
param([switch]$Force)
$ErrorActionPreference = 'Stop'

$isAdmin = [System.Security.Principal.WindowsPrincipal]::new(
    [System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw 'make-test-root writes machine-wide certificate stores and must run from an elevated terminal.'
}

$rootSubjectCn = 'DO_NOT_TRUST_FiddlerRoot'
$dn = "CN=$rootSubjectCn, O=DO_NOT_TRUST, OU=Created by http://www.fiddler2.com"

# GetRSAPrivateKey is an extension method, and PowerShell cannot call those with instance syntax.
$getRsaPrivateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions].GetMethod('GetRSAPrivateKey')

function Test-RootCandidate {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    $key = $null
    try {
        # HasPrivateKey only reports a key reference, so the honest test is to sign with it.
        $key = $getRsaPrivateKey.Invoke($null, [object[]]@($Cert))
        if (-not $key) { return $false }
        $key.SignData([byte[]](1, 2, 3, 4), [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1) | Out-Null
        return $true
    } catch {
        return $false
    } finally {
        if ($key) { $key.Dispose() }
    }
}

function Find-UsableRoot {
    $locations = @(
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    )

    # Multiple stores can contribute the same certificate: My has the signing context and Root has
    # the trust anchor. Collect trust first, then find usable copies in the personal stores.
    $trusted = @()
    foreach ($location in $locations) {
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
            [System.Security.Cryptography.X509Certificates.StoreName]::Root, $location)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        try {
            $found = @($store.Certificates.Find(
                [System.Security.Cryptography.X509Certificates.X509FindType]::FindBySubjectName,
                $rootSubjectCn, $false))
            $trusted += @($found | ForEach-Object { $_.Thumbprint })
        } finally {
            $store.Dispose()
        }
    }

    $candidates = @()
    foreach ($location in $locations) {
        foreach ($storeName in @(
            [System.Security.Cryptography.X509Certificates.StoreName]::My,
            [System.Security.Cryptography.X509Certificates.StoreName]::Root
        )) {
            $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($storeName, $location)
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            try {
                $candidates += @($store.Certificates.Find(
                    [System.Security.Cryptography.X509Certificates.X509FindType]::FindBySubjectName,
                    $rootSubjectCn, $false))
            } finally {
                $store.Dispose()
            }
        }
    }

    return @($candidates |
        Where-Object { $trusted -contains $_.Thumbprint -and (Test-RootCandidate -Cert $_) } |
        Sort-Object Thumbprint -Unique)
}

$existing = Find-UsableRoot
if ($existing.Count -gt 0 -and -not $Force) {
    throw "A usable $rootSubjectCn root is already installed ($($existing.Thumbprint -join ', ')). This script is " +
          'for a clean runner; pass -Force only if you mean to add a second one.'
}

$workdir = Join-Path ([System.IO.Path]::GetTempPath()) "tlsmitm-test-root-$PID"
New-Item -ItemType Directory -Path $workdir | Out-Null
try {
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    try {
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $dn, $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $req.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $true, 0, $true))
        $req.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
                [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor
                [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign, $true))
        $ekus = [System.Security.Cryptography.OidCollection]::new()
        [void]$ekus.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))
        $req.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($ekus, $false))
        $cert = $req.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(820))
    } finally {
        $rsa.Dispose()
    }

    # Missing enum members are silently zero in PowerShell unless StrictMode is enabled. Fail at the
    # fixture boundary if the generated CA cannot actually certify leaves, rather than 20 seconds
    # later on the first TLS handshake.
    $keyUsage = @($cert.Extensions | Where-Object {
        $_ -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]
    }) | Select-Object -First 1
    if (-not $keyUsage -or -not $keyUsage.KeyUsages.HasFlag(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign)) {
        throw 'Generated root is missing the KeyCertSign key-usage bit.'
    }

    # The same failure class for the other extension that decides whether a leaf can chain: a fixture
    # looser than production certifies chains the real root would refuse. .NET exposes no path-length
    # property, so this compares the encoded extension against the DER measured on a Fiddler machine.
    $basic = @($cert.Extensions | Where-Object {
        $_ -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]
    }) | Select-Object -First 1
    $expectedBasicConstraints = [byte[]](0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x00)
    if (-not $basic -or -not $basic.CertificateAuthority -or
        -not [System.Linq.Enumerable]::SequenceEqual([byte[]]$basic.RawData, $expectedBasicConstraints)) {
        throw ('Generated root does not encode basicConstraints as CA=TRUE with pathLen 0 ' +
               "($($expectedBasicConstraints -join ' ')), the measured real root's DER.")
    }

    # The password guards nothing: the key is generated here, the PFX is deleted when this block
    # finishes, and the private key lives on only in the personal store. PFX import requires an
    # encrypted container.
    $password = ConvertTo-SecureString -String ([guid]::NewGuid().ToString('N')) -AsPlainText -Force
    $pfxPath = Join-Path $workdir 'root.pfx'
    $cerPath = Join-Path $workdir 'root.cer'
    [System.IO.File]::WriteAllBytes($pfxPath,
        $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx,
            (ConvertFrom-SecureString $password -AsPlainText)))
    [System.IO.File]::WriteAllBytes($cerPath, $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))

    # Keep the key and trust anchor separate, as Fiddler does. Add the PFX to LocalMachine\My with
    # MachineKeySet|PersistKeySet so the key survives this process, then add only the public
    # certificate to LocalMachine\Root. Both stores are writable by this elevated process and neither
    # takes the interactive CurrentUser trust-consent path.
    Write-Host '[make-test-root] importing private key into LocalMachine\My'
    $keyFlags = (
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
    $pfxBytes = [System.IO.File]::ReadAllBytes($pfxPath)
    $persisted = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $pfxBytes, $password, $keyFlags)
    try {
        $myStore = [System.Security.Cryptography.X509Certificates.X509Store]::new(
            [System.Security.Cryptography.X509Certificates.StoreName]::My,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
        $myStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        try {
            $myStore.Add($persisted)
        } finally {
            $myStore.Dispose()
        }
    } finally {
        $persisted.Dispose()
        [System.Array]::Clear($pfxBytes, 0, $pfxBytes.Length)
    }

    Write-Host '[make-test-root] adding trust anchor to LocalMachine\Root'
    $cerBytes = [System.IO.File]::ReadAllBytes($cerPath)
    $trustedCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cerBytes)
    try {
        $rootStore = [System.Security.Cryptography.X509Certificates.X509Store]::new(
            [System.Security.Cryptography.X509Certificates.StoreName]::Root,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
        $rootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        try {
            $rootStore.Add($trustedCert)
        } finally {
            $rootStore.Dispose()
        }
    } finally {
        $trustedCert.Dispose()
    }

    $installed = Find-UsableRoot
    if ($installed.Count -eq 0) {
        throw 'The root was installed but no copy with a usable private key is trusted in a Root store. ' +
              'The private key import did not produce a signing certificate that RootCa can use.'
    }
    foreach ($c in $installed) {
        Write-Host "[make-test-root] usable root $($c.Thumbprint), valid until $($c.NotAfter.ToString('yyyy-MM-dd'))"
    }
} finally {
    Remove-Item -Recurse -Force $workdir -ErrorAction SilentlyContinue
}
