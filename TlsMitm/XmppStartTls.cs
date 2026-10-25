using System.Text;

namespace TlsMitm;

internal enum XmppMark
{
    None,
    Command,
    Granted,
    Declined
}

/// <summary>
/// Reads the STARTTLS exchange of one direction of an XMPP stream, which is an element rather than a
/// line: the client sends a &lt;starttls/&gt; and the server answers with &lt;proceed/&gt; or
/// &lt;failure/&gt;, each qualified by the 'urn:ietf:params:xml:ns:xmpp-tls' namespace
/// (RFC 6120 §5.4.2.1, §5.4.2.2, §5.4.2.3).
/// The two directions look for different elements because the server also puts a &lt;starttls/&gt; on the
/// wire before any command: §5.4.1 requires the stream features to advertise STARTTLS with exactly that
/// element, so a scanner that hunted for it in server-to-client text would read the advertisement as the
/// grant. Only the element's own tag counts, which is how the RFC spells it.
/// The boundary is the closing '&gt;' of the start tag, not the end of a line: §5.4.2.3 has both entities
/// "consider the TLS negotiation to have begun immediately after" that character, so what follows is the
/// handshake. §5.4.2 defines the command and the grant as empty elements, so this is also their end.
/// A stream this scanner finds nothing in is relayed rather than decrypted; the grant stays a grant
/// between the two peers.
/// </summary>
internal sealed class XmppScanner
{
    private const string TlsNamespace = "urn:ietf:params:xml:ns:xmpp-tls";

    // A tag name can be split across two writes, so the tail of one chunk has to be readable as the head
    // of the next. This much of the stream is enough for any tag name used here, and dropping older text
    // can only cost a detection, never invent a grant.
    private const int Carry = 16;

    // An opening tag that stays open past this many octets is not one of the elements defined here,
    // however it began: RFC 6120 §5.4.2 spells the command, the grant and the failure as short empty
    // elements, so the namespace and the closing '&gt;' are always near the '&lt;' that opened them.
    // Giving up is what keeps a stream that only looks like a match from growing this scanner forever.
    private const int StartTagCap = 1024;

    private readonly bool _clientSide;
    private readonly string _commandTag;
    private readonly string? _declineTag;
    private string _pending = "";
    private bool _done;

    public XmppScanner(bool clientSide)
    {
        _clientSide = clientSide;
        _commandTag = clientSide ? "<starttls" : "<proceed";
        _declineTag = clientSide ? null : "<failure";
    }

    /// <summary>
    /// Consumes one chunk and returns how many of ITS octets still belong to the plaintext session: all
    /// of them unless an element completed, in which case everything up to and including its closing
    /// '&gt;'. Latin-1 maps each octet to one char, so these offsets are byte offsets.
    /// </summary>
    public int Scan(ReadOnlySpan<byte> data, out XmppMark mark)
    {
        mark = XmppMark.None;
        if (_done) return data.Length;

        var carried = _pending.Length;
        var text = _pending + Encoding.Latin1.GetString(data);

        for (var from = 0; ; )
        {
            var (open, declined) = FindTag(text, from);
            if (open < 0)
            {
                _pending = text[Math.Max(0, text.Length - Carry)..];
                return data.Length;
            }

            var close = EndOfTag(text, open);
            if (close < 0)
            {
                if (text.Length - open > StartTagCap) _done = true;
                else _pending = text[open..];
                return data.Length;
            }

            if (text.AsSpan(open, close - open + 1).IndexOf(TlsNamespace, StringComparison.Ordinal) >= 0)
            {
                _pending = "";
                _done = true;
                mark = _clientSide ? XmppMark.Command
                    : declined ? XmppMark.Declined : XmppMark.Granted;
                return Math.Min(data.Length, Math.Max(0, close + 1 - carried));
            }

            // Qualified by some other namespace, so not this protocol's element: look after it.
            from = close + 1;
        }
    }

    private (int Index, bool Declined) FindTag(string text, int from)
    {
        var command = text.IndexOf(_commandTag, from, StringComparison.Ordinal);
        if (_declineTag == null) return (command, false);

        var decline = text.IndexOf(_declineTag, from, StringComparison.Ordinal);
        if (decline < 0) return (command, false);
        if (command < 0 || decline < command) return (decline, true);
        return (command, false);
    }

    // The closing '>' is looked for outside quoted attribute runs, so a '>' carried inside an attribute
    // value cannot end the tag early. -1 means the tag is not closed yet in the text at hand.
    private static int EndOfTag(string text, int open)
    {
        char quote = '\0';
        for (var i = open + 1; i < text.Length; i++)
        {
            var c = text[i];
            if (quote != '\0')
            {
                if (c == quote) quote = '\0';
                continue;
            }
            if (c == '\'' || c == '"') quote = c;
            else if (c == '>') return i;
        }
        return -1;
    }
}
