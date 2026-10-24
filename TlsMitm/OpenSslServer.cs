using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TlsMitm;

// SChannel builds a credential's chain from the local stores and transmits exactly that chain; an
// extra store passed in SCHANNEL_CRED is not consulted (measured: the same two certificates reached
// the wire with an empty store, a populated store and no store at all). The emSign chain - a leaf
// issued by an intermediate whose private scalar is known, plus the cross-signed root - therefore
// needs an engine that sends exactly the chain it is handed. That is libssl.
internal static class OpenSsl
{
    private const string Lib = "libssl-3-x64.dll";
    // d2i_*, X509_free, EVP_PKEY_free and ERR_* are libcrypto exports, not libssl ones.
    private const string CryptoLib = "libcrypto-3-x64.dll";

    public const int SSL_ERROR_NONE = 0;
    public const int SSL_ERROR_SSL = 1;
    public const int SSL_ERROR_WANT_READ = 2;
    public const int SSL_ERROR_WANT_WRITE = 3;
    public const int SSL_ERROR_SYSCALL = 5;
    public const int SSL_ERROR_ZERO_RETURN = 6;

    public const int BIO_CTRL_PENDING = 10;
    public const int SSL_TLSEXT_ERR_OK = 0;
    public const int SSL_TLSEXT_ERR_NOACK = 3;

    private static bool _loaded;
    private static Exception? _loadFailure;

    public static void EnsureLoaded()
    {
        if (_loaded) return;
        if (_loadFailure != null) throw new InvalidOperationException(_loadFailure.Message, _loadFailure);

        var errors = new List<string>();
        var pairs = new List<(string Ssl, string Crypto)>
        {
            // A copy beside the executable wins, so a different OpenSSL build can be dropped in
            // without a rebuild; otherwise the pair embedded in this assembly is unpacked into a
            // per-user directory, exactly as the WinDivert driver is.
            (Path.Combine(AppContext.BaseDirectory, Lib), Path.Combine(AppContext.BaseDirectory, CryptoLib)),
        };
        try { pairs.Add(ExtractEmbeddedPair()); }
        catch (Exception ex) { errors.Add("embedded pair: " + ex.Message); }

        foreach (var (sslPath, cryptoPath) in pairs)
        {
            if (!File.Exists(sslPath) || !File.Exists(cryptoPath)) continue;
            try
            {
                // libcrypto first: libssl resolves it by base name, and ExplicitLoad would rather
                // match the copy beside the libssl we actually picked than whatever is on PATH.
                NativeLibrary.Load(cryptoPath);
                NativeLibrary.Load(sslPath);
                _loaded = true;
                Console.WriteLine($"[OpenSSL] {VersionText()} loaded from {sslPath}");
                return;
            }
            catch (Exception ex)
            {
                errors.Add($"{sslPath}: {ex.Message}");
            }
        }

        _loadFailure = new InvalidOperationException(
            "libssl-3-x64.dll could not be loaded; tried: " + string.Join("; ", errors.DefaultIfEmpty("no candidate path exists")));
        throw _loadFailure;
    }

    // Unpacked once per user. The extracted copy is replaced whenever its digest no longer matches the
    // embedded one, so an upgrade never runs against a stale file that merely happens to share a length.
    private static (string Ssl, string Crypto) ExtractEmbeddedPair()
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "TlsMitm", "openssl-3");
        return (Extract(Lib), Extract(CryptoLib));

        string Extract(string name)
        {
            using var stream = typeof(OpenSsl).Assembly.GetManifestResourceStream("TlsMitm.openssl." + name)
                ?? throw new InvalidOperationException($"{name} is not embedded in this build");
            var path = Path.Combine(dir, name);
            var expected = SHA256.HashData(stream);
            if (File.Exists(path))
            {
                using var existing = File.OpenRead(path);
                if (SHA256.HashData(existing).SequenceEqual(expected)) return path;
            }
            Directory.CreateDirectory(dir);
            stream.Position = 0;
            using var fs = File.Create(path);
            stream.CopyTo(fs);
            return path;
        }
    }

    public static string VersionText() =>
        // t = 0 is OPENSSL_VERSION_TEXT in openssl/crypto.h.
        Marshal.PtrToStringAnsi(OpenSSL_version(0)) ?? "unknown";

    public static string LastError()
    {
        var code = ERR_get_error();
        if (code == 0) return "no error queued";
        var buf = new byte[256];
        ERR_error_string_n(code, buf, (uint)buf.Length);
        var end = Array.IndexOf(buf, (byte)0);
        return System.Text.Encoding.ASCII.GetString(buf, 0, end < 0 ? buf.Length : end);
    }

    public static IntPtr ParseCertificate(byte[] der)
    {
        var data = Marshal.AllocHGlobal(der.Length);
        var cursor = Marshal.AllocHGlobal(IntPtr.Size);
        try
        {
            Marshal.Copy(der, 0, data, der.Length);
            Marshal.WriteIntPtr(cursor, data);
            var x = d2i_X509(IntPtr.Zero, cursor, der.Length);
            if (x == IntPtr.Zero) throw new InvalidOperationException($"d2i_X509: {LastError()}");
            return x;
        }
        finally
        {
            Marshal.FreeHGlobal(cursor);
            Marshal.FreeHGlobal(data);
        }
    }

    public static IntPtr ParsePrivateKey(byte[] pkcs8)
    {
        var data = Marshal.AllocHGlobal(pkcs8.Length);
        var cursor = Marshal.AllocHGlobal(IntPtr.Size);
        try
        {
            Marshal.Copy(pkcs8, 0, data, pkcs8.Length);
            Marshal.WriteIntPtr(cursor, data);
            var key = d2i_AutoPrivateKey(IntPtr.Zero, cursor, pkcs8.Length);
            if (key == IntPtr.Zero) throw new InvalidOperationException($"d2i_AutoPrivateKey: {LastError()}");
            return key;
        }
        finally
        {
            Marshal.FreeHGlobal(cursor);
            Marshal.FreeHGlobal(data);
        }
    }

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] public static extern IntPtr TLS_server_method();
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] public static extern IntPtr SSL_CTX_new(IntPtr method);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] public static extern void SSL_CTX_free(IntPtr ctx);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] public static extern int SSL_CTX_use_certificate(IntPtr ctx, IntPtr x509);
    // SSL_CTX_add1_chain_cert is a macro over this control code, not an exported symbol.
    public const int SSL_CTRL_CHAIN_CERT = 89;
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] public static extern long SSL_CTX_ctrl(IntPtr ctx, int cmd, long larg, IntPtr parg);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] public static extern int SSL_CTX_use_PrivateKey(IntPtr ctx, IntPtr pkey);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] public static extern int SSL_CTX_check_private_key(IntPtr ctx);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] public static extern void SSL_CTX_set_alpn_select_cb(IntPtr ctx, IntPtr cb, IntPtr arg);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] public static extern IntPtr SSL_new(IntPtr ctx);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] public static extern void SSL_set_accept_state(IntPtr ssl);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] public static extern void SSL_free(IntPtr ssl);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] public static extern void SSL_set_bio(IntPtr ssl, IntPtr rbio, IntPtr wbio);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] public static extern int SSL_do_handshake(IntPtr ssl);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] public static extern int SSL_get_error(IntPtr ssl, int ret);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] public static extern int SSL_read(IntPtr ssl, byte[] buf, int num);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] public static extern int SSL_write(IntPtr ssl, byte[] buf, int num);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] public static extern int SSL_shutdown(IntPtr ssl);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] public static extern void SSL_get0_alpn_selected(IntPtr ssl, out IntPtr data, out uint len);

    [DllImport(CryptoLib, CallingConvention = CallingConvention.Cdecl)] public static extern IntPtr BIO_s_mem();
    [DllImport(CryptoLib, CallingConvention = CallingConvention.Cdecl)] public static extern IntPtr BIO_new(IntPtr type);
    [DllImport(CryptoLib, CallingConvention = CallingConvention.Cdecl)] public static extern void BIO_free(IntPtr bio);
    [DllImport(CryptoLib, CallingConvention = CallingConvention.Cdecl)] public static extern int BIO_write(IntPtr bio, byte[] data, int len);
    [DllImport(CryptoLib, CallingConvention = CallingConvention.Cdecl)] public static extern int BIO_read(IntPtr bio, byte[] data, int len);
    [DllImport(CryptoLib, CallingConvention = CallingConvention.Cdecl)] public static extern int BIO_ctrl(IntPtr bio, int cmd, int larg, IntPtr parg);

    [DllImport(CryptoLib, CallingConvention = CallingConvention.Cdecl)] public static extern ulong ERR_get_error();
    [DllImport(CryptoLib, CallingConvention = CallingConvention.Cdecl)] public static extern void ERR_error_string_n(ulong e, byte[] buf, uint len);

    [DllImport(CryptoLib, CallingConvention = CallingConvention.Cdecl)] private static extern IntPtr d2i_X509(IntPtr a, IntPtr pp, int length);
    [DllImport(CryptoLib, CallingConvention = CallingConvention.Cdecl)] private static extern IntPtr d2i_AutoPrivateKey(IntPtr a, IntPtr pp, int length);
    [DllImport(CryptoLib, CallingConvention = CallingConvention.Cdecl)] public static extern void X509_free(IntPtr x);
    [DllImport(CryptoLib, CallingConvention = CallingConvention.Cdecl)] public static extern void EVP_PKEY_free(IntPtr key);

    // Returns a pointer to a static, internally-allocated string owned by OpenSSL; PtrToStringAnsi
    // copies it, so there is nothing to free and no lifetime to manage.
    [DllImport(CryptoLib, CallingConvention = CallingConvention.Cdecl)] private static extern IntPtr OpenSSL_version(int t);
}

/// <summary>
/// TLS server leg backed by libssl so the exact chain handed to the client reaches the wire.
/// Transport I/O goes through memory BIOs, which lets the bytes already consumed while parsing the
/// ClientHello (SNI/ALPN/blind-relay decision) be replayed instead of re-read from the socket.
/// Both relay directions share one SSL object, which is not thread-safe, so every libssl call runs
/// under one lock; the lock is never held while waiting for bytes from the peer.
/// </summary>
public sealed class OpenSslServerStream : Stream
{
    private static readonly OpenSslAlpnSelect AlpnCallback = SelectAlpn;
    private static readonly IntPtr AlpnCallbackPtr = Marshal.GetFunctionPointerForDelegate(AlpnCallback);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int OpenSslAlpnSelect(IntPtr ssl, ref IntPtr outp, ref byte outlen, IntPtr inp, uint inlen, IntPtr arg);

    private readonly Stream _transport;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private IntPtr _ctx;
    private IntPtr _ssl;
    private IntPtr _rbio;
    private IntPtr _wbio;
    private readonly byte[] _io = new byte[16384];
    private bool _disposed;

    public string NegotiatedProtocol { get; private set; } = "";

    private OpenSslServerStream(Stream transport, IntPtr ctx, IntPtr ssl, IntPtr rbio, IntPtr wbio)
    {
        _transport = transport;
        _ctx = ctx;
        _ssl = ssl;
        _rbio = rbio;
        _wbio = wbio;
    }

    /// <summary>
    /// Runs the server handshake over <paramref name="transport"/>, replaying the ClientHello bytes
    /// the caller already consumed. <paramref name="alpn"/> is the protocol the upstream leg settled
    /// on; null selects none, which leaves HTTP clients on HTTP/1.1.
    /// </summary>
    public static async Task<OpenSslServerStream> AcceptAsync(
        Stream transport, ReadOnlyMemory<byte> replayedClientHello, X509Certificate2 leaf,
        X509Certificate2Collection? chain, string? alpn, CancellationToken ct)
    {
        OpenSsl.EnsureLoaded();

        var ctx = OpenSsl.SSL_CTX_new(OpenSsl.TLS_server_method());
        if (ctx == IntPtr.Zero) throw new InvalidOperationException($"SSL_CTX_new: {OpenSsl.LastError()}");

        IntPtr leafX509 = IntPtr.Zero, key = IntPtr.Zero, ssl = IntPtr.Zero, rbio = IntPtr.Zero, wbio = IntPtr.Zero;
        GCHandle? alpnPin = null;
        var chainCerts = new List<IntPtr>();
        try
        {
            leafX509 = OpenSsl.ParseCertificate(leaf.Export(X509ContentType.Cert));
            if (OpenSsl.SSL_CTX_use_certificate(ctx, leafX509) != 1)
                throw new InvalidOperationException($"SSL_CTX_use_certificate: {OpenSsl.LastError()}");

            if (chain != null)
            {
                foreach (var c in chain)
                {
                    var x = OpenSsl.ParseCertificate(c.Export(X509ContentType.Cert));
                    chainCerts.Add(x);
                    // larg=1 is add1: up-ref, so freeing our copy leaves the context's intact.
                    if (OpenSsl.SSL_CTX_ctrl(ctx, OpenSsl.SSL_CTRL_CHAIN_CERT, 1, x) != 1)
                        throw new InvalidOperationException($"SSL_CTX_add1_chain_cert ({c.Subject}): {OpenSsl.LastError()}");
                }
            }

            using (var privateKey = (AsymmetricAlgorithm?)leaf.GetRSAPrivateKey() ?? leaf.GetECDsaPrivateKey())
            {
                if (privateKey == null)
                    throw new InvalidOperationException($"leaf {leaf.Subject} has no usable private key");
                key = OpenSsl.ParsePrivateKey(privateKey.ExportPkcs8PrivateKey());
            }
            if (OpenSsl.SSL_CTX_use_PrivateKey(ctx, key) != 1)
                throw new InvalidOperationException($"SSL_CTX_use_PrivateKey: {OpenSsl.LastError()}");
            if (OpenSsl.SSL_CTX_check_private_key(ctx) != 1)
                throw new InvalidOperationException($"SSL_CTX_check_private_key: {OpenSsl.LastError()}");

            // The callback argument is per context, and this context serves one connection, so the
            // negotiated protocol rides there instead of in per-SSL ex-data (a macro, not a symbol).
            if (alpn != null)
            {
                alpnPin = GCHandle.Alloc(System.Text.Encoding.ASCII.GetBytes(alpn), GCHandleType.Pinned);
                OpenSsl.SSL_CTX_set_alpn_select_cb(ctx, AlpnCallbackPtr, GCHandle.ToIntPtr(alpnPin.Value));
            }

            ssl = OpenSsl.SSL_new(ctx);
            if (ssl == IntPtr.Zero) throw new InvalidOperationException($"SSL_new: {OpenSsl.LastError()}");
            // SSL_new leaves the role unset; without this SSL_do_handshake fails with
            // "connection type not set" rather than picking the server state machine.
            OpenSsl.SSL_set_accept_state(ssl);

            rbio = OpenSsl.BIO_new(OpenSsl.BIO_s_mem());
            wbio = OpenSsl.BIO_new(OpenSsl.BIO_s_mem());
            if (rbio == IntPtr.Zero || wbio == IntPtr.Zero)
                throw new InvalidOperationException($"BIO_new: {OpenSsl.LastError()}");

            var stream = new OpenSslServerStream(transport, ctx, ssl, rbio, wbio);
            OpenSsl.SSL_set_bio(ssl, rbio, wbio);   // ownership of both BIOs moves to the SSL object
            ssl = rbio = wbio = IntPtr.Zero;
            ctx = IntPtr.Zero;                      // the stream frees the context

            try
            {
                if (replayedClientHello.Length > 0)
                    await stream.WriteInAsync(replayedClientHello, ct);
                await stream.RunHandshakeAsync(ct);
                stream.CaptureNegotiatedProtocol();
                return stream;
            }
            catch
            {
                stream.Dispose();
                throw;
            }
        }
        finally
        {
            alpnPin?.Free();
            if (rbio != IntPtr.Zero) OpenSsl.BIO_free(rbio);
            if (wbio != IntPtr.Zero) OpenSsl.BIO_free(wbio);
            if (ssl != IntPtr.Zero) OpenSsl.SSL_free(ssl);
            if (key != IntPtr.Zero) OpenSsl.EVP_PKEY_free(key);
            if (leafX509 != IntPtr.Zero) OpenSsl.X509_free(leafX509);
            foreach (var x in chainCerts) OpenSsl.X509_free(x);
            if (ctx != IntPtr.Zero) OpenSsl.SSL_CTX_free(ctx);
        }
    }

    private static int SelectAlpn(IntPtr ssl, ref IntPtr outp, ref byte outlen, IntPtr inp, uint inlen, IntPtr arg)
    {
        if (arg == IntPtr.Zero) return OpenSsl.SSL_TLSEXT_ERR_NOACK;
        var handle = GCHandle.FromIntPtr(arg);
        var desired = ((byte[])handle.Target!).AsSpan();

        // The client's list is length-prefixed names in preference order (RFC 7301 §3.1). The answer
        // must point at memory that outlives the call, which the pinned protocol array does.
        var list = new byte[inlen];
        Marshal.Copy(inp, list, 0, list.Length);
        var offset = 0;
        while (offset < list.Length)
        {
            int len = list[offset];
            offset++;
            if (len == 0 || offset + len > list.Length) break;
            if (list.AsSpan(offset, len).SequenceEqual(desired))
            {
                outp = handle.AddrOfPinnedObject();
                outlen = (byte)len;
                return OpenSsl.SSL_TLSEXT_ERR_OK;
            }
            offset += len;
        }
        return OpenSsl.SSL_TLSEXT_ERR_NOACK;
    }

    private async Task RunHandshakeAsync(CancellationToken ct)
    {
        while (true)
        {
            int err;
            await _lock.WaitAsync(ct);
            try
            {
                var r = OpenSsl.SSL_do_handshake(_ssl);
                err = r == 1 ? OpenSsl.SSL_ERROR_NONE : OpenSsl.SSL_get_error(_ssl, r);
                await DrainLockedAsync(ct);
                if (r == 1) return;
            }
            finally
            {
                _lock.Release();
            }

            switch (err)
            {
                case OpenSsl.SSL_ERROR_WANT_READ:
                    if (!await FillInAsync(ct)) throw new IOException("client closed during the handshake");
                    continue;
                case OpenSsl.SSL_ERROR_WANT_WRITE:
                    continue;
                default:
                    throw new IOException($"SSL_do_handshake failed (ssl_error={err}): {OpenSsl.LastError()}");
            }
        }
    }

    private void CaptureNegotiatedProtocol()
    {
        OpenSsl.SSL_get0_alpn_selected(_ssl, out var data, out var len);
        if (data == IntPtr.Zero || len == 0) return;
        var bytes = new byte[len];
        Marshal.Copy(data, bytes, 0, (int)len);
        NegotiatedProtocol = System.Text.Encoding.ASCII.GetString(bytes);
    }

    private async Task WriteInAsync(ReadOnlyMemory<byte> bytes, CancellationToken ct)
    {
        var array = bytes.ToArray();
        await _lock.WaitAsync(ct);
        try
        {
            if (OpenSsl.BIO_write(_rbio, array, array.Length) != array.Length)
                throw new IOException($"BIO_write: {OpenSsl.LastError()}");
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<bool> FillInAsync(CancellationToken ct)
    {
        var n = await _transport.ReadAsync(_io, ct);
        if (n <= 0) return false;
        await _lock.WaitAsync(ct);
        try
        {
            if (OpenSsl.BIO_write(_rbio, _io, n) != n)
                throw new IOException($"BIO_write: {OpenSsl.LastError()}");
        }
        finally
        {
            _lock.Release();
        }
        return true;
    }

    private async Task DrainLockedAsync(CancellationToken ct)
    {
        while (true)
        {
            var pending = OpenSsl.BIO_ctrl(_wbio, OpenSsl.BIO_CTRL_PENDING, 0, IntPtr.Zero);
            if (pending <= 0) break;
            var n = OpenSsl.BIO_read(_wbio, _io, (int)Math.Min(pending, _io.Length));
            if (n <= 0) break;
            await _transport.WriteAsync(_io.AsMemory(0, n), ct);
        }
        await _transport.FlushAsync(ct);
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct)
    {
        if (buffer.Length == 0) return 0;
        var scratch = new byte[buffer.Length];
        while (true)
        {
            int err;
            await _lock.WaitAsync(ct);
            try
            {
                var r = OpenSsl.SSL_read(_ssl, scratch, scratch.Length);
                if (r > 0)
                {
                    scratch.AsSpan(0, r).CopyTo(buffer.Span);
                    await DrainLockedAsync(ct);
                    return r;
                }
                err = OpenSsl.SSL_get_error(_ssl, r);
                await DrainLockedAsync(ct);
                if (err == OpenSsl.SSL_ERROR_ZERO_RETURN) return 0;
                if (err != OpenSsl.SSL_ERROR_WANT_READ && err != OpenSsl.SSL_ERROR_WANT_WRITE)
                    throw new IOException($"SSL_read failed (ssl_error={err}): {OpenSsl.LastError()}");
            }
            finally
            {
                _lock.Release();
            }

            if (err == OpenSsl.SSL_ERROR_WANT_READ && !await FillInAsync(ct))
                return 0;
        }
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            int err;
            var needInput = false;
            await _lock.WaitAsync(ct);
            try
            {
                var chunk = buffer[offset..].ToArray();
                var r = OpenSsl.SSL_write(_ssl, chunk, chunk.Length);
                if (r > 0)
                {
                    offset += r;
                    await DrainLockedAsync(ct);
                    continue;
                }
                err = OpenSsl.SSL_get_error(_ssl, r);
                await DrainLockedAsync(ct);
                if (err == OpenSsl.SSL_ERROR_WANT_WRITE) continue;
                if (err == OpenSsl.SSL_ERROR_WANT_READ) needInput = true;
                else throw new IOException($"SSL_write failed (ssl_error={err}): {OpenSsl.LastError()}");
            }
            finally
            {
                _lock.Release();
            }

            if (needInput && !await FillInAsync(ct))
                throw new IOException("client closed mid-write");
        }
    }

    /// <summary>
    /// Sends close_notify and gives the peer a bounded window to answer: ending a TLS stream with a
    /// bare FIN reads as truncation to a strict peer, so the alert is what makes the EOF legitimate.
    /// </summary>
    public async Task ShutdownAsync(TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        try
        {
            await _lock.WaitAsync(cts.Token);
            try
            {
                OpenSsl.SSL_shutdown(_ssl);
                await DrainLockedAsync(cts.Token);
            }
            finally
            {
                _lock.Release();
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException)
        {
            // The peer is already gone; closing is all that is left.
        }
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override void Write(byte[] buffer, int offset, int count) =>
        WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override void Flush()
    {
        _lock.Wait();
        try { DrainLockedAsync(CancellationToken.None).GetAwaiter().GetResult(); }
        finally { _lock.Release(); }
    }

    public override async Task FlushAsync(CancellationToken ct)
    {
        await _lock.WaitAsync(ct);
        try { await DrainLockedAsync(ct); }
        finally { _lock.Release(); }
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (_disposed) return;
        _disposed = true;

        // SSL_free releases the BIOs it owns; the context is ours alone (one per connection).
        if (_ssl != IntPtr.Zero) { OpenSsl.SSL_free(_ssl); _ssl = IntPtr.Zero; }
        if (_ctx != IntPtr.Zero) { OpenSsl.SSL_CTX_free(_ctx); _ctx = IntPtr.Zero; }
        if (disposing) _transport.Dispose();
        base.Dispose(disposing);
    }
}
