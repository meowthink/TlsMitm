using System.Text;

namespace TlsMitm;

internal enum StartTlsOutcome
{
    Upgrade,
    Reject,
    Abort
}

/// <summary>
/// Watches a plaintext protocol session for a STARTTLS-style command and for the server's readiness
/// reply, as each protocol defines them: SMTP "STARTTLS" answered by 220 (RFC 3207 §4), IMAP
/// "&lt;tag&gt; STARTTLS" answered by a tagged OK (RFC 9051 §6.2.1), POP3 "STLS" answered by +OK
/// (RFC 2595 §4), FTP "AUTH TLS" answered by 234 (RFC 4217 §4.2), NNTP "STARTTLS" answered by 382
/// (RFC 4642 §2.2). LDAP has no line to read: its StartTLS is an extended operation in BER, so a
/// session whose first client octet is a SEQUENCE tag is handed to <see cref="LdapScanner"/>
/// (RFC 4511 §4.14) and the line scanner never sees it.
/// The client pump stops reading once the command is forwarded. In all of these protocols the handshake
/// begins only after the success reply: RFC 3207 §4 requires the client to start negotiating before
/// issuing any other command, RFC 9051 §6.2.1 and RFC 2595 §4 both say the negotiation starts
/// "immediately after the CRLF at the end of" the tagged OK / +OK, RFC 4217 §4.2 makes 234 the
/// reply that grants AUTH TLS, RFC 4642 §2.2 makes 382 the reply that grants TLS negotiation, and
/// RFC 4511 §4.14.1 forbids the LDAP client any further PDU until the response arrives.
/// No read is therefore in flight when both sockets are handed to SslStream.
/// </summary>
internal sealed class StartTlsSession
{
    private const int LineCap = 1024;

    private readonly StringBuilder _clientLine = new();
    private readonly StringBuilder _serverLine = new();
    private readonly TaskCompletionSource<StartTlsOutcome> _decision =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    private bool _clientLineOverflow;
    private bool _serverLineOverflow;
    private bool _smtpData;
    private long _skipBytes;
    private string? _imapTag;
    private volatile bool _awaitingReply;
    private int _state; // 0 none, 1 upgrade, 2 reject, 3 abort

    private LdapScanner? _ldapClient;
    private LdapScanner? _ldapServer;
    private bool _dialectDecided;

    public bool AwaitingReply => _awaitingReply;
    public Task<StartTlsOutcome> Decision => _decision.Task;
    public StartTlsOutcome? Result => Volatile.Read(ref _state) switch
    {
        1 => StartTlsOutcome.Upgrade,
        2 => StartTlsOutcome.Reject,
        3 => StartTlsOutcome.Abort,
        _ => null
    };

    /// <summary>Bytes received with the command that belong to the TLS handshake, not the plaintext session.</summary>
    public byte[] ClientRemainder { get; private set; } = Array.Empty<byte>();

    /// <summary>Server bytes that followed the readiness reply; they lead the upstream TLS stream.</summary>
    public byte[] ServerRemainder { get; private set; } = Array.Empty<byte>();

    public void ClearClientRemainder() => ClientRemainder = Array.Empty<byte>();

    public void Abort() => Complete(StartTlsOutcome.Abort);

    /// <summary>
    /// Consumes one client-to-server chunk. Returns how many bytes to forward. When a STARTTLS
    /// command is found, anything after its line is held back as TLS bytes.
    /// </summary>
    public int ScanClient(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0;

        if (!_dialectDecided)
        {
            _dialectDecided = true;
            // LDAP sends no greeting, so the client's first octet is the only thing that can name the
            // dialect before any of it is parsed: an LDAPMessage is a BER SEQUENCE (RFC 4511 §4.1.1)
            // and none of the line commands this file reads starts with 0x30.
            if (data[0] == 0x30)
            {
                _ldapClient = new LdapScanner(clientSide: true);
                _ldapServer = new LdapScanner(clientSide: false);
            }
        }

        return _ldapClient == null ? ScanClientLines(data) : ScanClientLdap(data);
    }

    private int ScanClientLdap(ReadOnlySpan<byte> data)
    {
        var end = _ldapClient!.Scan(data, out var decision);
        if (decision != LdapDecision.Requested) return data.Length;

        _ldapServer!.StartTlsMessageId = _ldapClient.StartTlsMessageId;
        _awaitingReply = true;
        ClientRemainder = data[end..].ToArray();
        return end;
    }

    private int ScanClientLines(ReadOnlySpan<byte> data)
    {
        for (var i = 0; i < data.Length; i++)
        {
            if (_skipBytes > 0)
            {
                _skipBytes--;
                continue;
            }

            var b = data[i];
            if (b != (byte)'\n')
            {
                Append(_clientLine, ref _clientLineOverflow, b);
                continue;
            }

            var overflow = _clientLineOverflow;
            var raw = _clientLine.ToString().TrimEnd('\r');
            _clientLine.Clear();
            _clientLineOverflow = false;
            if (overflow) continue;

            // Message bodies and literals carry arbitrary text; a line inside them is not a command.
            // SMTP: DATA (RFC 5321 §4.1.1.4) ends at a line containing only "." (RFC 5321 §4.5.2).
            if (_smtpData)
            {
                if (raw == ".") _smtpData = false;
                continue;
            }

            var line = raw.Trim();
            if (line.Length == 0) continue;
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var verb = parts[0].ToUpperInvariant();

            if (verb == "DATA")
            {
                _smtpData = true;
                continue;
            }
            // RFC 3030 §2 sends the message data immediately after the CRLF of BDAT, so exactly those
            // octets must never be scanned for a verb.
            if (verb == "BDAT" && parts.Length >= 2 && long.TryParse(parts[1], out var count) && count >= 0)
            {
                _skipBytes = count;
                continue;
            }
            // IMAP literal (RFC 9051 §4.3). Both forms put the octets in the next n bytes this client
            // sends: "{n+}" sends them immediately, and "{n}" waits for the command continuation
            // request first, which arrives from the server and not from this stream.
            if (line.EndsWith('}') && TryParseLiteral(line, out var literal))
            {
                _skipBytes = literal;
                continue;
            }

            // Command forms: SMTP "STARTTLS" (RFC 3207 §4), POP3 "STLS" (RFC 2595 §4), FTP "AUTH TLS"
            // (RFC 4217 §4.1, and §17 makes 'TLS' the mechanism name the client MUST use). IMAP alone
            // prefixes a tag, defined by RFC 9051 §2.2.1 and shown for this command in §6.2.1; the tag
            // is kept because the completion reply repeats it.
            string? imapTag = null;
            var isStartTls = verb == "STARTTLS" || verb == "STLS" ||
                (verb == "AUTH" && parts.Length >= 2 && IsTlsMechanism(parts[1]));
            if (!isStartTls && parts.Length >= 2 &&
                parts[1].Equals("STARTTLS", StringComparison.OrdinalIgnoreCase))
            {
                imapTag = parts[0];
                isStartTls = true;
            }
            if (!isStartTls) continue;

            _imapTag = imapTag;
            _awaitingReply = true;
            ClientRemainder = data[(i + 1)..].ToArray();
            return i + 1;
        }

        return data.Length;
    }

    /// <summary>
    /// Consumes one server-to-client chunk. Returns how many bytes to forward; on success the bytes
    /// after the final reply line lead the upstream TLS stream, on rejection everything is forwarded
    /// and the plaintext session resumes. SMTP and FTP allow a multi-line reply (RFC 5321 §4.2.1,
    /// RFC 959 §4.2), so only the last line of one decides.
    /// The line dialects are only readable once a command is pending, so they are skipped until then.
    /// LDAP is read from its first octet instead: a BER walker that joins the stream late cannot tell
    /// where one message ends, and losing that boundary loses the messageID the grant is matched by.
    /// </summary>
    public int ScanServer(ReadOnlySpan<byte> data)
    {
        if (_ldapServer != null) return ScanServerLdap(data);
        return _awaitingReply ? ScanServerLines(data) : data.Length;
    }

    private int ScanServerLdap(ReadOnlySpan<byte> data)
    {
        var end = _ldapServer!.Scan(data, out var decision);
        if (decision is not (LdapDecision.Granted or LdapDecision.Declined)) return data.Length;

        // RFC 4511 §4.14.2: a response that is not success leaves the session without a TLS layer, so
        // the refusal is relayed and the plaintext session carries on. That outcome is fixed once: it
        // was either reached here or on an earlier chunk, and what follows is then only counted to keep
        // the walk in step with the message boundaries, never acted on.
        if (decision == LdapDecision.Declined || Result != null)
        {
            Complete(StartTlsOutcome.Reject);
            _ldapServer.Scan(data[end..], out _);
            return data.Length;
        }

        ServerRemainder = data[end..].ToArray();
        Complete(StartTlsOutcome.Upgrade);
        return end;
    }

    private int ScanServerLines(ReadOnlySpan<byte> data)
    {
        for (var i = 0; i < data.Length; i++)
        {
            var b = data[i];
            if (b != (byte)'\n')
            {
                Append(_serverLine, ref _serverLineOverflow, b);
                continue;
            }

            var overflow = _serverLineOverflow;
            var line = _serverLine.ToString().TrimEnd('\r');
            _serverLine.Clear();
            _serverLineOverflow = false;
            if (overflow) continue;

            if (!IsFinalReplyLine(line)) continue;

            var success = IsSuccessReply(line);
            ServerRemainder = success ? data[(i + 1)..].ToArray() : Array.Empty<byte>();
            Complete(success ? StartTlsOutcome.Upgrade : StartTlsOutcome.Reject);
            return success ? i + 1 : data.Length;
        }

        return data.Length;
    }

    private void Complete(StartTlsOutcome outcome)
    {
        var value = outcome switch
        {
            StartTlsOutcome.Upgrade => 1,
            StartTlsOutcome.Reject => 2,
            _ => 3
        };
        if (Interlocked.CompareExchange(ref _state, value, 0) != 0) return;
        if (outcome != StartTlsOutcome.Upgrade) _awaitingReply = false;
        _decision.TrySetResult(outcome);
    }

    // RFC 4217 §4.2 makes 234 the reply that grants "AUTH TLS", and §17 names 'TLS' as the mechanism a
    // client MUST use. The older "AUTH SSL" spelling is tolerated on the strength of §8 alone: the
    // SSL/TLS protocols self-negotiate their level, so "there is no need to distinguish between SSL and
    // TLS in the application layer". A server that has no such mechanism answers with any other final
    // line, which is a decline and leaves the plaintext tunnel running, so the alias costs nothing.
    private static bool IsTlsMechanism(string token) =>
        token.Equals("TLS", StringComparison.OrdinalIgnoreCase) ||
        token.Equals("SSL", StringComparison.OrdinalIgnoreCase);

    private static void Append(StringBuilder sb, ref bool overflow, byte b)
    {
        if (overflow) return;
        if (sb.Length < LineCap) sb.Append((char)b);
        else
        {
            overflow = true;
            sb.Clear();
        }
    }

    // IMAP client literals: "A001 LOGIN {10}" is followed by exactly ten raw octets.
    private static bool TryParseLiteral(string line, out long count)
    {
        count = 0;
        var open = line.LastIndexOf('{');
        if (open < 0) return false;
        var digitsEnd = line.Length - 1; // index of '}'
        if (digitsEnd > open && line[digitsEnd - 1] == '+') digitsEnd--;
        if (digitsEnd <= open + 1) return false;
        return long.TryParse(line.AsSpan(open + 1, digitsEnd - open - 1), out count) && count >= 0;
    }

    // The numeric a reply line carries, and whether it completes the command. SMTP, FTP and NNTP all
    // answer with a bare "NNN text".
    private static bool TryReplyCode(string line, out string code, out bool final)
    {
        code = "";
        final = false;

        if (line.Length < 3 ||
            !char.IsAsciiDigit(line[0]) || !char.IsAsciiDigit(line[1]) || !char.IsAsciiDigit(line[2]))
        {
            return false;
        }

        code = line.Substring(0, 3);
        final = line.Length == 3 || line[3] != '-';
        return true;
    }

    private bool IsFinalReplyLine(string line)
    {
        // SMTP/FTP: "250-" continues the reply, "250 " (or bare "250") ends it (RFC 5321 §4.2.1,
        // RFC 959 §4.2).
        if (TryReplyCode(line, out _, out var final)) return final;

        // POP3 has exactly two response indicators, "+OK" and "-ERR" (RFC 1939 §3). Some POP3 replies
        // are multi-line there, terminated by a line holding a single '.', but RFC 2595 §4 states the
        // STLS answer as a single-line +OK, which is what ends this command for us.
        if (line.StartsWith("+OK", StringComparison.OrdinalIgnoreCase) ||
            line.StartsWith("-ERR", StringComparison.OrdinalIgnoreCase)) return true;

        // IMAP completion line; untagged "*" and continuation "+" lines are not completions, and a
        // tagged OK/NO/BAD ends the command (RFC 9051 §7.1).
        return _imapTag != null && line.StartsWith(_imapTag + " ", StringComparison.Ordinal);
    }

    private bool IsSuccessReply(string line)
    {
        if (line.StartsWith("+OK", StringComparison.OrdinalIgnoreCase)) return true;   // RFC 2595 §4
        if (_imapTag != null && line.StartsWith(_imapTag + " OK", StringComparison.Ordinal)) return true;

        if (!TryReplyCode(line, out var code, out _)) return false;

        // 220 is SMTP's "Ready to start TLS" (RFC 3207 §4) and 234 grants FTP's AUTH TLS (RFC 4217 §4.2).
        // 382 is NNTP's "Continue with TLS negotiation" (RFC 4642 §2.2). 220 is accepted for FTP as well,
        // where RFC 959 §4.2.1 defines it as the service-ready greeting.
        //
        // Each is a tolerance rather than an RFC provision, and not a free one: once a reply is read as
        // the grant the two sockets go straight to the TLS handshake with no way back to the plaintext
        // tunnel, so a server that means something else by that code loses the session. What bounds the
        // risk is that ScanServer only runs after a STARTTLS-shaped command was forwarded, so a code
        // belonging to some other command can never be read as a grant here.
        return code == "220" || code == "234" || code == "382";
    }
}
