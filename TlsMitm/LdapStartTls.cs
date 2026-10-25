namespace TlsMitm;

internal enum LdapDecision
{
    None,
    Requested,
    Granted,
    Declined
}

/// <summary>
/// Walks one direction of an LDAP session as BER instead of as lines. RFC 4511 §4.1.1 defines
/// LDAPMessage as "SEQUENCE { messageID, protocolOp, controls [0] OPTIONAL }", §4.12 gives
/// ExtendedRequest [APPLICATION 23] and ExtendedResponse [APPLICATION 24], §4.14.1 fixes requestName
/// at 1.3.6.1.4.1.1466.20037 and requires that the client "MUST NOT send any LDAP PDUs ... until it
/// receives a StartTLS Extended response", and §4.14.2 makes the grant an ExtendedResponse whose
/// resultCode is success (0), leaving the session without a TLS layer on any other code. §4.1.1.1
/// makes a response carry its request's messageID, which is what separates the grant from the
/// response to some other extended operation.
/// Messages are counted, never buffered: an entry of any size is skipped by its own length, so the
/// scanner holds nothing but the octets that follow the deciding message.
/// </summary>
internal sealed class LdapScanner
{
    private const byte TagSequence = 0x30;
    private const byte TagInteger = 0x02;
    private const byte TagExtendedRequest = 0x77;
    private const byte TagExtendedResponse = 0x78;

    // The first element each side leads its Extended operation with: requestName is [0] inside
    // ExtendedRequest (RFC 4511 §4.12), while ExtendedResponse starts with LDAPResult's resultCode,
    // an ENUMERATED (RFC 4511 §4.1.9, and §4.12 splices those components in ahead of responseName).
    private const byte TagRequestName = 0x80;
    private const byte TagEnumerated = 0x0A;
    private const long ResultCodeSuccess = 0;

    // The definite form only, per RFC 4511 §5.1. wldap32 pads its long forms to four octets
    // (measured: "30 84 00 00 00 21"), so a long form is read by its own octet count rather than
    // assumed to be the shortest one. Eight octets is the most a long counter here can hold.
    private const int MaxLengthOctets = 8;

    // RFC 4511 §4.1.1 requires both a messageID and a protocolOp, so the shortest content an
    // LDAPMessage can carry is "02 01 xx" plus an op tag and its length.
    private const int MinMessageContent = 5;

    // 1.3.6.1.4.1.1466.20037 as an LDAPOID, which RFC 4511 §4.1.2 defines as the UTF-8
    // dotted-decimal text of the identifier in an OCTET STRING rather than its DER encoding.
    // RFC 4532 §2.1 shows the same text form for the whoami OID it sits beside.
    private static readonly byte[] StartTlsOid =
        "1.3.6.1.4.1.1466.20037"u8.ToArray();

    private enum Phase { SeqTag, Length, IdTag, IdValue, OpTag, InnerTag, InnerValue, Tail }
    private enum LengthTarget { Message, MessageId, ProtocolOp, Inner }

    private readonly bool _clientSide;

    private Phase _phase = Phase.SeqTag;
    private LengthTarget _lengthTarget;
    private int _lengthOctetsLeft;
    private long _lengthValue;
    private long _messageLeft;
    private long _valueLeft;
    private long _value;
    private long _messageId;
    private long _resultCode = -1;
    private byte _opTag;
    private int _oidIndex;
    private bool _isStartTls;

    public LdapScanner(bool clientSide) => _clientSide = clientSide;

    /// <summary>
    /// Set by the client side when it reads a StartTLS request; the server side only acts on an
    /// ExtendedResponse carrying this messageID. Zero means no request has been seen, which also
    /// excludes the unsolicited notifications RFC 4511 §4.1.1.1 reserves messageID 0 for.
    /// </summary>
    public long StartTlsMessageId { get; set; }

    /// <summary>The stream is not LDAP this scanner can follow; the session is relayed untouched.</summary>
    public bool Invalid { get; private set; }

    /// <summary>
    /// Consumes one chunk. Returns the index just past the message that decided the exchange, or
    /// data.Length when the whole chunk is ordinary traffic; the decision says which.
    /// </summary>
    public int Scan(ReadOnlySpan<byte> data, out LdapDecision decision)
    {
        decision = LdapDecision.None;
        if (Invalid) return data.Length;

        for (var i = 0; i < data.Length; i++)
        {
            var b = data[i];
            var isMessageContent = _phase != Phase.SeqTag &&
                !(_phase == Phase.Length && _lengthTarget == LengthTarget.Message);

            switch (_phase)
            {
                case Phase.SeqTag:
                    if (b != TagSequence)
                    {
                        Invalid = true;
                        return data.Length;
                    }
                    Enter(LengthTarget.Message);
                    break;

                case Phase.Length:
                    if (_lengthOctetsLeft > 0)
                    {
                        _lengthValue = (_lengthValue << 8) | b;
                        if (--_lengthOctetsLeft > 0) break;
                    }
                    else if (b < 0x80)
                    {
                        _lengthValue = b;
                    }
                    // 0x80 is the indefinite form RFC 4511 §5.1 rules out, and 0xFF is reserved by
                    // X.690 §8.1.3.5 for future extensions.
                    else if (b == 0x80 || b == 0xFF || (b & 0x7F) > MaxLengthOctets)
                    {
                        Invalid = true;
                        return data.Length;
                    }
                    else
                    {
                        _lengthOctetsLeft = b & 0x7F;
                        _lengthValue = 0;
                        break;
                    }

                    _lengthOctetsLeft = 0;
                    switch (_lengthTarget)
                    {
                        case LengthTarget.Message:
                            if (_lengthValue < MinMessageContent)
                            {
                                Invalid = true;
                                return data.Length;
                            }
                            _messageLeft = _lengthValue;
                            _phase = Phase.IdTag;
                            break;
                        case LengthTarget.MessageId:
                            if (_lengthValue < 1 || _lengthValue > MaxLengthOctets)
                            {
                                Invalid = true;
                                return data.Length;
                            }
                            _valueLeft = _lengthValue;
                            _value = 0;
                            _phase = Phase.IdValue;
                            break;
                        case LengthTarget.ProtocolOp:
                            _phase = IsTargetOp(_opTag) ? Phase.InnerTag : Phase.Tail;
                            break;
                        default:
                            _valueLeft = _lengthValue;
                            if (_valueLeft == 0)
                            {
                                // An empty requestName cannot be the StartTLS OID and an empty
                                // resultCode cannot be success, so neither ends the exchange.
                                _phase = Phase.Tail;
                            }
                            else
                            {
                                _value = 0;
                                _oidIndex = 0;
                                _phase = Phase.InnerValue;
                            }
                            break;
                    }
                    break;

                case Phase.IdTag:
                    if (b != TagInteger)
                    {
                        Invalid = true;
                        return data.Length;
                    }
                    Enter(LengthTarget.MessageId);
                    break;

                case Phase.IdValue:
                    _value = (_value << 8) | b;
                    if (--_valueLeft == 0)
                    {
                        _messageId = _value;
                        _phase = Phase.OpTag;
                    }
                    break;

                case Phase.OpTag:
                    _opTag = b;
                    Enter(LengthTarget.ProtocolOp);
                    break;

                case Phase.InnerTag:
                    // Anything other than that first element is an operation this scanner has no
                    // business with, and the message is passed over by its own length.
                    if (b != (_clientSide ? TagRequestName : TagEnumerated))
                    {
                        _phase = Phase.Tail;
                        break;
                    }
                    Enter(LengthTarget.Inner);
                    break;

                case Phase.InnerValue:
                    if (_clientSide)
                    {
                        var matched = _oidIndex >= 0 && _oidIndex < StartTlsOid.Length &&
                            b == StartTlsOid[_oidIndex];
                        _oidIndex = matched ? _oidIndex + 1 : -1;
                    }
                    else
                    {
                        _value = (_value << 8) | b;
                    }
                    if (--_valueLeft == 0) FinishValue();
                    break;

                case Phase.Tail:
                    break;
            }

            if (!isMessageContent) continue;
            if (--_messageLeft > 0) continue;

            decision = MessageComplete();
            if (decision != LdapDecision.None) return i + 1;
        }

        return data.Length;
    }

    private void Enter(LengthTarget target)
    {
        _lengthTarget = target;
        _lengthOctetsLeft = 0;
        _lengthValue = 0;
        _phase = Phase.Length;
    }

    private void FinishValue()
    {
        if (_clientSide) _isStartTls = _oidIndex == StartTlsOid.Length;
        else _resultCode = _value;
        _phase = Phase.Tail;
    }

    private bool IsTargetOp(byte tag) =>
        _clientSide ? tag == TagExtendedRequest : tag == TagExtendedResponse;

    private LdapDecision MessageComplete()
    {
        var decision = LdapDecision.None;
        if (_clientSide)
        {
            if (_isStartTls && _messageId != 0) decision = LdapDecision.Requested;
        }
        else if (_opTag == TagExtendedResponse && StartTlsMessageId != 0 && _messageId == StartTlsMessageId)
        {
            decision = _resultCode == ResultCodeSuccess ? LdapDecision.Granted : LdapDecision.Declined;
        }

        if (decision == LdapDecision.Requested) StartTlsMessageId = _messageId;
        _phase = Phase.SeqTag;
        _opTag = 0;
        _messageId = 0;
        _resultCode = -1;
        _isStartTls = false;
        _oidIndex = 0;
        _value = 0;
        _valueLeft = 0;
        return decision;
    }
}
