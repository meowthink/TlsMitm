namespace TlsMitm;

internal enum SunRpcMark
{
    None,
    Probe,
    Granted,
    Declined
}

/// <summary>
/// Walks one direction of an RPC-over-TCP session as records instead of as lines. RFC 5531 §11 puts a
/// four-octet header in front of every fragment: the highest-order bit tells whether that fragment is the
/// last of its record, and the 31 low-order bits are the fragment's length in octets. One RPC message fits
/// into one record, so a record is the whole CALL or REPLY this exchange turns on, however the stream
/// splits it.
/// The client side watches each record for the probe RFC 9289 §4.1 defines: a CALL (msgtype 0, rpcvers 2,
/// RFC 5531 §9) whose procedure is the NULL procedure, whose credential is flavor AUTH_TLS (7, RFC 9289
/// §7.1) with a length of zero octets, and whose verifier is AUTH_NONE (RFC 5531 §9) with a length of zero
/// octets. Those fixed values and the two unconstrained program fields make the probe record 40 octets long,
/// which is the length of an ordinary NULL call too, so it is the credential's flavor that separates the two.
/// The server side decides on the reply to it, and RFC 5531 §9 has that reply carry the call's xid
/// unchanged. Per §4.1 the grant is a reply_stat of MSG_ACCEPTED (0) whose verifier is AUTH_NONE over eight
/// octets spelling "STARTTLS", and the client then proceeds with TLS whatever the accept_stat says; §4.1
/// rules out a ClientHello for every other reply, so each is a decline that leaves the RPC session in
/// plaintext.
/// Records are counted, not buffered: only the octets a decision reads are held, so a record of any size
/// passes through by its own length.
/// </summary>
internal sealed class SunRpcScanner
{
    private const uint MsgTypeCall = 0;
    private const uint MsgTypeReply = 1;
    private const uint RpcVersion = 2;
    private const uint NullProcedure = 0;
    private const uint AuthNone = 0;      // RFC 5531 §9
    private const uint AuthTls = 7;       // RFC 9289 §7.1
    private const uint MsgAccepted = 0;   // RFC 5531 §9
    private const uint LastFragmentBit = 0x8000_0000u;

    // xid, msgtype, rpcvers, prog, vers, proc, then the credential's and the verifier's flavor and length:
    // 6 words plus two 2-word opaque_auths.
    private const int ProbeLength = 40;

    // A grant reads xid, msgtype, reply_stat, the verifier's flavor and length and its token, and the
    // accept_stat after them - present because §4.1 only ever speaks of an accepted reply's status, and free
    // to say anything because that is what §4.1 makes it. Results of any length may sit behind the prefix,
    // so this is a prefix, not a record length.
    private const int ReplyHeadLength = 32;

    private const int TokenOffset = 20;
    private const uint TokenLength = 8;

    private readonly bool _clientSide;
    private readonly int _cap;
    private readonly byte[] _body = new byte[ProbeLength];

    private uint _headerWord;
    private int _headerOctetsLeft = 4;
    private long _fragmentLeft;
    private bool _lastFragment;
    private long _recordLength;
    private int _held;

    public SunRpcScanner(bool clientSide)
    {
        _clientSide = clientSide;
        _cap = clientSide ? ProbeLength : ReplyHeadLength;
    }

    /// <summary>
    /// The xid of the probe the client side read, which the server side matches its reply by. Held as a
    /// nullable rather than as a sentinel: RFC 5531 §9 puts the xid to use for a client matching replies
    /// with calls and for a server detecting retransmissions, so any value, 0 among them, can open a session.
    /// </summary>
    public uint? ProbeXid { get; set; }

    /// <summary>
    /// Consumes one chunk. Returns the index just past the record that decided the exchange, or data.Length
    /// when the whole chunk is ordinary traffic; the mark says which.
    /// </summary>
    public int Scan(ReadOnlySpan<byte> data, out SunRpcMark mark)
    {
        mark = SunRpcMark.None;
        for (var i = 0; i < data.Length; i++)
        {
            var b = data[i];
            if (_fragmentLeft > 0)
            {
                if (_held < _cap) _body[_held++] = b;
                _recordLength++;
                if (--_fragmentLeft > 0 || !_lastFragment) continue;

                mark = EndRecord();
                if (mark != SunRpcMark.None) return i + 1;
                continue;
            }

            _headerWord = _headerWord << 8 | b;
            if (--_headerOctetsLeft > 0) continue;

            _lastFragment = (_headerWord & LastFragmentBit) != 0;
            _fragmentLeft = _headerWord & 0x7FFF_FFFFu;
            _headerWord = 0;
            _headerOctetsLeft = 4;

            // §11 allows a fragment of zero octets, so an empty last fragment ends its record here rather
            // than waiting for data that never comes.
            if (_fragmentLeft > 0 || !_lastFragment) continue;
            mark = EndRecord();
            if (mark != SunRpcMark.None) return i + 1;
        }

        return data.Length;
    }

    private SunRpcMark EndRecord()
    {
        var mark = _clientSide ? ReadProbe() : ReadReply();
        _recordLength = 0;
        _held = 0;
        return mark;
    }

    private SunRpcMark ReadProbe()
    {
        if (_recordLength != ProbeLength) return SunRpcMark.None;
        if (Word(4) != MsgTypeCall || Word(8) != RpcVersion || Word(20) != NullProcedure)
            return SunRpcMark.None;
        // §4.1 requires both zero lengths, so a credential that carries bytes is not this probe; the record
        // is relayed and the session is left as the client and server made it.
        if (Word(24) != AuthTls || Word(28) != 0 || Word(32) != AuthNone || Word(36) != 0)
            return SunRpcMark.None;

        ProbeXid = Word(0);
        return SunRpcMark.Probe;
    }

    private SunRpcMark ReadReply()
    {
        if (ProbeXid == null || _held < 12) return SunRpcMark.None;
        if (Word(0) != ProbeXid || Word(4) != MsgTypeReply) return SunRpcMark.None;

        // §4.1's three ways to withhold the grant - a reply_stat other than MSG_ACCEPTED, a verifier of
        // another flavor, a verifier without the token - all end the same way, so they are one decision here.
        if (Word(8) != MsgAccepted) return SunRpcMark.Declined;
        if (_held < TokenOffset + 8 || Word(12) != AuthNone || Word(16) != TokenLength)
            return SunRpcMark.Declined;

        var token = new ReadOnlySpan<byte>(_body, TokenOffset, 8);
        return token.SequenceEqual("STARTTLS"u8) ? SunRpcMark.Granted : SunRpcMark.Declined;
    }

    private uint Word(int offset) =>
        (uint)(_body[offset] << 24 | _body[offset + 1] << 16 | _body[offset + 2] << 8 | _body[offset + 3]);
}
