using System.Formats.Asn1;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace TlsMitm;

// A verifier may establish non-revocation "by obtaining the appropriate CRL, by status information,
// or by out-of-band mechanisms" (RFC 5280 §6.1.3(a)(3)), and §6.3 makes the CRL algorithm optional as
// long as an equivalent mechanism exists. curl's Schannel chooses to fail closed (measured: it
// returns CRYPT_E_NO_REVOCATION_CHECK, and an unreachable pointer only moves the failure to
// CRYPT_E_REVOCATION_OFFLINE). Signing a CRL with the same root that signs the leaves and serving it
// from loopback gives the chain a real answer - "not revoked" - instead of an unknowable one.
public sealed class CrlService : IDisposable
{
    private static readonly int[] CandidatePorts = { 8873, 8874, 8875, 8876, 8877 };
    private static readonly TimeSpan Validity = TimeSpan.FromDays(7);

    private readonly X509Certificate2 _ca;
    private readonly byte[] _ski;
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly object _gate = new();
    private byte[]? _der;
    private DateTimeOffset _builtAt;
    private Task? _acceptLoop;

    public int Port { get; }
    public string Url { get; }
    public string RequestPath { get; }

    private CrlService(X509Certificate2 ca, TcpListener listener, int port, byte[] ski)
    {
        _ca = ca;
        _ski = ski;
        _listener = listener;
        Port = port;
        RequestPath = $"/crl/{ca.Thumbprint.ToLowerInvariant()}.crl";
        Url = $"http://127.0.0.1:{port}{RequestPath}";
    }

    public static CrlService? Start(X509Certificate2 ca)
    {
        if (ca.GetRSAPrivateKey() == null)
        {
            Console.WriteLine("[CRL] The signing CA has no RSA key, leaves stay without a CRL pointer");
            return null;
        }

        var ski = TryReadSubjectKeyIdentifier(ca);

        foreach (var port in CandidatePorts)
        {
            TcpListener listener;
            try
            {
                listener = new TcpListener(IPAddress.Loopback, port);
                listener.Start();
            }
            catch (SocketException)
            {
                continue;
            }

            var service = new CrlService(ca, listener, port, ski);
            byte[] der;
            try
            {
                der = service.EnsureCrl();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[CRL] Signing failed, leaves stay without a CRL pointer: {ex.Message}");
                listener.Stop();
                return null;
            }

            service._acceptLoop = service.AcceptLoopAsync();
            Console.WriteLine($"[CRL] Serving {service.Url} ({der.Length} bytes, empty list, {Validity.TotalDays:0}d validity)");
            return service;
        }

        Console.WriteLine("[CRL] No loopback port available, leaves stay without a CRL pointer");
        return null;
    }

    public bool Serves(X509Certificate2 issuer) => issuer.Thumbprint == _ca.Thumbprint;

    public byte[] EnsureCrl()
    {
        lock (_gate)
        {
            // Re-sign well before the published nextUpdate so a long-running process never serves a CRL
            // a client has to go and replace: RFC 5280 §6.3.3(a)(1) says that once the current time is
            // after nextUpdate, the client must obtain a delta or complete CRL and re-verify the time
            // against the one it just fetched, and §5.1.2.5 requires us to publish nextUpdate at all.
            // Clients keep the copy they already fetched meanwhile.
            if (_der != null && DateTimeOffset.UtcNow - _builtAt < Validity / 2) return _der;

            _der = BuildCrl();
            _builtAt = DateTimeOffset.UtcNow;
            return _der;
        }
    }

    private byte[] BuildCrl()
    {
        var thisUpdate = DateTimeOffset.UtcNow.AddHours(-1);
        var nextUpdate = DateTimeOffset.UtcNow + Validity;

        var tbs = new AsnWriter(AsnEncodingRules.DER);
        using (tbs.PushSequence())
        {
            // Version 2 is mandatory once extensions appear (RFC 5280 §5.1.2.1); the signature
            // algorithm here must equal the one outside tbsCertList (§5.1.2.2, §5.1.1.2), which
            // WriteSignatureAlgorithm guarantees. That the issuer is the CA's own name comes from
            // §4.1.2.6, which requires a CRL issuer's subject to match the issuer field of every CRL it
            // issues; §5.1.2.3 then makes that field a non-empty DN encoded by the certificate's rules
            // (§4.1.2.4), so the CA's SubjectName.RawData can be written verbatim.
            tbs.WriteInteger(1);                       // v2, mandatory once crlExtensions appear
            WriteSignatureAlgorithm(tbs);
            tbs.WriteEncodedValue(_ca.SubjectName.RawData);
            // thisUpdate/nextUpdate are §5.1.2.4 and §5.1.2.5: the latter requires conforming issuers to
            // include nextUpdate in every CRL, and both are UTCTime for dates through 2049.
            tbs.WriteUtcTime(thisUpdate);
            tbs.WriteUtcTime(nextUpdate);

            using (tbs.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            {
                using (tbs.PushSequence())             // Extensions SEQUENCE OF
                {
                    // RFC 5280 §5.2 requires both of these in every CRL; §5.2.1 requires the key
                    // identifier form (the CA's subjectKeyIdentifier, §4.2.1.2).
                    if (_ski.Length > 0)
                    {
                        var aki = new AsnWriter(AsnEncodingRules.DER);
                        using (aki.PushSequence())
                            aki.WriteOctetString(_ski, new Asn1Tag(TagClass.ContextSpecific, 0, false));
                        WriteExtension(tbs, "2.5.29.35", aki.Encode());
                    }

                    // RFC 5280 §5.2.3: MUST be present, MUST be non-critical, and MUST increase
                    // between two CRLs for the same scope. Time in seconds is monotonic across a
                    // process restart, which a counter reset to 1 would not be.
                    var number = new AsnWriter(AsnEncodingRules.DER);
                    number.WriteInteger(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                    WriteExtension(tbs, "2.5.29.20", number.Encode());
                }
            }
        }

        var tbsDer = tbs.Encode();
        using var rsa = _ca.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("the CA private key is not usable");
        var signature = rsa.SignData(tbsDer, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var crl = new AsnWriter(AsnEncodingRules.DER);
        using (crl.PushSequence())
        {
            crl.WriteEncodedValue(tbsDer);
            WriteSignatureAlgorithm(crl);
            crl.WriteBitString(signature);
        }
        return crl.Encode();
    }

    private static void WriteSignatureAlgorithm(AsnWriter writer)
    {
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier("1.2.840.113549.1.1.11");   // sha256WithRSAEncryption
            writer.WriteNull();
        }
    }

    private static void WriteExtension(AsnWriter writer, string oid, byte[] value)
    {
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(oid);
            writer.WriteOctetString(value);
        }
    }

    private static byte[] TryReadSubjectKeyIdentifier(X509Certificate2 ca)
    {
        // subjectKeyIdentifier is RFC 5280 §4.2.1.2 (MUST be non-critical); §5.2.1 derives the CRL's
        // authorityKeyIdentifier from it.
        var extension = ca.Extensions["2.5.29.14"];
        if (extension == null) return Array.Empty<byte>();
        return new AsnReader(extension.RawData, AsnEncodingRules.DER).ReadOctetString();
    }

    // RFC 5280 §4.2.1.13: cRLDistributionPoints is SEQUENCE OF DistributionPoint, whose fullName [0]
    // is an IMPLICIT GeneralNames - the ASN.1 module is defined with IMPLICIT TAGS (§A.2; §A.1 is the
    // explicitly-tagged one) - so there is no SEQUENCE wrapper inside the second [0]. A real VeriSign
    // CDP is 30283026a024a0228620..., and an extra 30 here parses as no URL at all on Windows.
    // §4.2.1.13 also requires the URI to point to a single DER-encoded CRL, which is exactly what
    // HandleAsync serves.
    public static byte[] DistributionPoints(string url)
    {
        var dp = new Asn1Tag(TagClass.ContextSpecific, 0, true);
        var uri = new Asn1Tag(TagClass.ContextSpecific, 6, false);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                using (writer.PushSequence(dp))
                {
                    using (writer.PushSequence(dp))
                        writer.WriteCharacterString(UniversalTagNumber.IA5String, url, uri);
                }
            }
        }
        return writer.Encode();
    }

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(_cts.Token);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }

            _ = HandleAsync(client);
        }
    }

    private async Task HandleAsync(TcpClient client)
    {
        var peer = client.Client.RemoteEndPoint;
        try
        {
            using (client)
            {
                var stream = client.GetStream();
                var head = await ReadHeadAsync(stream, _cts.Token);
                var target = head?.Split("\r\n", 2)[0].Split(' ') is { Length: >= 2 } parts ? parts[1] : null;

                if (target != RequestPath)
                {
                    Console.WriteLine($"[CRL] {peer} asked for '{target ?? "<nothing>"}', not serving it");
                    await RespondAsync(stream, "404 Not Found", "text/plain", Encoding.ASCII.GetBytes("no\n"));
                    return;
                }

                var der = EnsureCrl();
                await RespondAsync(stream, "200 OK", "application/pkix-crl", der);
                Console.WriteLine($"[CRL] Sent {der.Length} bytes to {peer}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[CRL] {peer}: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private static async Task<string?> ReadHeadAsync(Stream stream, CancellationToken ct)
    {
        var buffer = new byte[2048];
        var length = 0;
        while (length < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(length), ct);
            if (read == 0) return null;
            length += read;
            if (buffer.AsSpan(0, length).IndexOf("\r\n\r\n"u8) >= 0) break;
        }
        return Encoding.ASCII.GetString(buffer, 0, length);
    }

    private static async Task RespondAsync(Stream stream, string status, string contentType, byte[] body)
    {
        var head = Encoding.ASCII.GetBytes(
            $"HTTP/1.1 {status}\r\nContent-Type: {contentType}\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(head);
        if (body.Length > 0) await stream.WriteAsync(body);
        await stream.FlushAsync();
    }

    public void Dispose()
    {
        _cts.Cancel();
        _listener.Stop();
        try { _acceptLoop?.Wait(TimeSpan.FromSeconds(1)); } catch { }
        _cts.Dispose();
    }
}
