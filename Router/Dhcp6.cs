using System.Buffers.Binary;
using System.Net;

namespace Router;

// RFC 8415 §7.3 lists the message types and their numbers.
public enum Dhcp6Kind : byte
{
    Solicit = 1, Advertise = 2, Request = 3, Confirm = 4, Renew = 5, Rebind = 6, Reply = 7, Release = 8, Decline = 9,
}

// RFC 8415 §7.1 names the link-scoped address a client uses to reach a server; the scope id that makes it
// sendable belongs to the socket, not to this constant.
public static class Dhcp6
{
    // §7.2: "Clients listen for DHCP messages on UDP port 546. Servers and relay agents listen for DHCP
    // messages on UDP port 547."
    public const int ClientPort = 546;
    public const int ServerPort = 547;
    public const string AllRelayAgentsAndServers = "ff02::1:2";

    // Option codes, §21.
    public const ushort OptClientId = 1;
    public const ushort OptServerId = 2;
    public const ushort OptOro = 6;
    public const ushort OptElapsedTime = 8;
    public const ushort OptStatusCode = 13;
    public const ushort OptDnsServers = 23;
    public const ushort OptIaPd = 25;
    public const ushort OptIaPrefix = 26;
    public const ushort OptSolMaxRt = 82;

    // §21.13.
    public const ushort StatusSuccess = 0;
    public const ushort StatusNoBinding = 3;
    public const ushort StatusNoPrefixAvail = 6;

    // §7.7: 0xffffffff means "infinity" in a lifetime, and also in T1 or T2.
    public const uint Infinity = 0xFFFFFFFF;

    // §11.4 Figure 7: DUID-Type 3, a 2-octet hardware type (1 is Ethernet) and the link-layer address.
    public static byte[] DuidLl(byte[] mac)
    {
        var duid = new byte[4 + mac.Length];
        duid[1] = 3;
        duid[3] = 1;
        mac.CopyTo(duid, 4);
        return duid;
    }

    public static byte[] Iapd(uint iaid, uint t1, uint t2, params Dhcp6Option[] inner)
    {
        var length = 12;
        foreach (var option in inner) length += 4 + option.Data.Length;
        var data = new byte[length];
        BinaryPrimitives.WriteUInt32BigEndian(data, iaid);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(4), t1);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(8), t2);
        WriteOptions(data.AsSpan(12), inner);
        return data;
    }

    // §21.22: preferred-lifetime, valid-lifetime, prefix-length, then the 16-octet prefix. A hint has a
    // zero prefix (§18.2.4 allows a zero IPv6-prefix only as a length hint).
    public static byte[] IaPrefix(uint preferred, uint valid, byte length, byte[] prefix)
    {
        var data = new byte[25];
        BinaryPrimitives.WriteUInt32BigEndian(data, preferred);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(4), valid);
        data[8] = length;
        prefix.AsSpan(0, Math.Min(16, prefix.Length)).CopyTo(data.AsSpan(9));
        return data;
    }

    public static bool TryParseIapd(ReadOnlySpan<byte> data, out uint iaid, out uint t1, out uint t2,
        out Iaprefix? prefix, out ushort status, out string why)
    {
        iaid = t1 = t2 = 0;
        prefix = null;
        status = StatusSuccess;
        why = "";
        if (data.Length < 12)
        {
            why = $"IA_PD is {data.Length} octets; its fixed part is 12";
            return false;
        }
        iaid = BinaryPrimitives.ReadUInt32BigEndian(data);
        t1 = BinaryPrimitives.ReadUInt32BigEndian(data[4..]);
        t2 = BinaryPrimitives.ReadUInt32BigEndian(data[8..]);
        for (var i = 12; i < data.Length;)
        {
            if (i + 4 > data.Length)
            {
                why = "an IA_PD sub-option header runs past the option";
                return false;
            }
            var code = BinaryPrimitives.ReadUInt16BigEndian(data[i..]);
            var length = BinaryPrimitives.ReadUInt16BigEndian(data[(i + 2)..]);
            if (i + 4 + length > data.Length)
            {
                why = $"IA_PD sub-option {code} claims {length} octets past the option";
                return false;
            }
            var body = data.Slice(i + 4, length);
            if (code == OptIaPrefix)
            {
                if (length < 25)
                {
                    why = $"IA Prefix is {length} octets; its fixed part is 25";
                    return false;
                }
                prefix = new Iaprefix(
                    new Dhcp6Prefix(body[8], body.Slice(9, 16).ToArray()),
                    BinaryPrimitives.ReadUInt32BigEndian(body),
                    BinaryPrimitives.ReadUInt32BigEndian(body[4..]));
            }
            else if (code == OptStatusCode)
            {
                if (length < 2)
                {
                    why = $"Status Code is {length} octets; it needs at least 2";
                    return false;
                }
                status = BinaryPrimitives.ReadUInt16BigEndian(body);
            }
            i += 4 + length;
        }
        return true;
    }

    public static void WriteOptions(Span<byte> target, IEnumerable<Dhcp6Option> options)
    {
        var offset = 0;
        foreach (var option in options)
        {
            BinaryPrimitives.WriteUInt16BigEndian(target[offset..], option.Code);
            BinaryPrimitives.WriteUInt16BigEndian(target[(offset + 2)..], (ushort)option.Data.Length);
            option.Data.CopyTo(target[(offset + 4)..]);
            offset += 4 + option.Data.Length;
        }
    }
}

public readonly record struct Dhcp6Option(ushort Code, byte[] Data);

// §21.22's prefix and the two lifetimes that travel with it. Lifetimes stay in the server's unit (seconds)
// so the client converts them exactly once, when it turns them into deadlines.
public readonly record struct Iaprefix(Dhcp6Prefix Prefix, uint Preferred, uint Valid);

public readonly record struct Dhcp6Prefix(byte Length, byte[] Address)
{
    public static byte[] ZeroAddress() => new byte[16];

    public bool IsZero => Address.All(value => value == 0);

    public bool SameAs(Dhcp6Prefix other) => Length == other.Length && Address.AsSpan().SequenceEqual(other.Address);

    public override string ToString() => $"{new IPAddress(Address)}/{Length}";

    // A server is supposed to send masked host bits, and masking again costs nothing, while stray host bits
    // in a route or a Router Advertisement would be a real fault.
    public Dhcp6Prefix Masked()
    {
        var bytes = (byte[])Address.Clone();
        for (var bit = Length; bit < 128; bit++) bytes[bit / 8] &= (byte)~(0x80 >> (bit % 8));
        return new Dhcp6Prefix(Length, bytes);
    }

    // SLAAC forms a 64-bit interface identifier (RFC 4862 §5.5), so a prefix longer than /64 cannot be
    // advertised for the LAN at all.
    public bool TryLanSubnet(out Dhcp6Prefix subnet)
    {
        if (Length > 64)
        {
            subnet = default;
            return false;
        }
        subnet = new Dhcp6Prefix(64, (byte[])Address.Clone()).Masked();
        return true;
    }
}

public sealed class Dhcp6Message
{
    public Dhcp6Message(Dhcp6Kind kind, uint transactionId, IReadOnlyList<Dhcp6Option> options)
    {
        Kind = kind;
        TransactionId = transactionId;
        Options = options;
    }

    public Dhcp6Kind Kind { get; }

    // §8: the field is three octets, so only the low 24 bits are ever carried.
    public uint TransactionId { get; }

    public IReadOnlyList<Dhcp6Option> Options { get; }

    public Dhcp6Option? First(ushort code)
    {
        foreach (var option in Options)
            if (option.Code == code) return option;
        return null;
    }

    // The codes a message carried, in order, plus its top-level status when it named one. A server's refusal
    // and a message this client misread look the same in a "carried no X" line, and only the contents tell
    // the two apart, so the contents are what a failed exchange puts on the record.
    public string Describe()
    {
        var text = "options " + string.Join(',', Options.Select(option => option.Code));
        return First(Dhcp6.OptStatusCode)?.Data is { Length: >= 2 } status
            ? text + $" with status {BinaryPrimitives.ReadUInt16BigEndian(status)}"
            : text;
    }

    public static bool TryParse(ReadOnlySpan<byte> datagram, out Dhcp6Message? message, out string why)
    {
        message = null;
        why = "";
        if (datagram.Length < 4)
        {
            why = $"a DHCPv6 message needs a 4-octet header, this one has {datagram.Length}";
            return false;
        }
        if (!Enum.IsDefined(typeof(Dhcp6Kind), (Dhcp6Kind)datagram[0]))
        {
            // §16: "A client or server MUST discard any received DHCP messages with an unknown message type."
            why = $"message type {datagram[0]} is not one this client knows";
            return false;
        }
        var transactionId = (uint)(datagram[1] << 16 | datagram[2] << 8 | datagram[3]);
        var options = new List<Dhcp6Option>();
        for (var i = 4; i < datagram.Length;)
        {
            if (i + 4 > datagram.Length)
            {
                why = "an option header runs past the end of the message";
                return false;
            }
            var code = BinaryPrimitives.ReadUInt16BigEndian(datagram[i..]);
            var length = BinaryPrimitives.ReadUInt16BigEndian(datagram[(i + 2)..]);
            if (i + 4 + length > datagram.Length)
            {
                why = $"option {code} claims {length} octets past the end of the message";
                return false;
            }
            // §16 names an unknown option as something to ignore, so it is kept but never consulted.
            options.Add(new Dhcp6Option(code, datagram.Slice(i + 4, length).ToArray()));
            i += 4 + length;
        }
        message = new Dhcp6Message((Dhcp6Kind)datagram[0], transactionId, options);
        return true;
    }

    public byte[] Build()
    {
        var size = 4;
        foreach (var option in Options) size += 4 + option.Data.Length;
        var buffer = new byte[size];
        buffer[0] = (byte)Kind;
        buffer[1] = (byte)(TransactionId >> 16);
        buffer[2] = (byte)(TransactionId >> 8);
        buffer[3] = (byte)TransactionId;
        Dhcp6.WriteOptions(buffer.AsSpan(4), Options);
        return buffer;
    }
}

// What the caller has to do after a step of the exchange: the socket shell sends what a PdTransmit carries
// to All_DHCP_Relay_Agents_and_Servers, and the address side installs or removes the LAN prefix on what the
// other two carry. There is no unicast variant: RFC 8415 §14 makes that address the destination of a client's
// messages, and names a server by its Server Identifier option inside the message rather than by where the
// datagram is sent. §21.12's Server Unicast option is the one thing that licenses unicast, and this client
// neither asks for it nor handles it - measured 2026-10-31, this upstream answers a unicast Request with
// status 5, UseMulticast (§21.13), and never offers the option.
public abstract record PdStep;
public sealed record PdTransmit(byte[] Datagram, string Note) : PdStep;
public sealed record PdDelegated(Dhcp6Prefix Prefix, TimeSpan Preferred, TimeSpan Valid, string Server,
    IReadOnlyList<byte[]> Dns, string Note) : PdStep;
public sealed record PdWithdrawn(Dhcp6Prefix? Prefix, string Why) : PdStep;

public enum PdState { Starting, Soliciting, Requesting, Bound, Renewing, Rebinding, Released, Failed }

// A DHCPv6 client for one IA_PD. It owns the message exchange and nothing else: no socket, no route, no
// clock of its own, so every transition can be driven offline with a fake clock and hand-built messages.
public sealed class PdClient
{
    // Table 1 in §7.6.
    private static readonly TimeSpan SolTimeout = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan SolMaxDelay = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan ReqTimeout = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan ReqMaxRt = TimeSpan.FromSeconds(30);
    private const int ReqMaxRc = 10;
    private static readonly TimeSpan RenTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan RenMaxRt = TimeSpan.FromSeconds(600);
    private static readonly TimeSpan RebTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan RebMaxRt = TimeSpan.FromSeconds(600);
    private static readonly TimeSpan RetryAfterLoss = TimeSpan.FromSeconds(60);

    private readonly byte[] _duid;
    private readonly uint _iaid;
    private readonly byte _wantLength;
    private readonly Func<double> _random;

    private PdState _state = PdState.Starting;
    private uint _transactionId;
    private DateTime _exchangeStart;
    private TimeSpan _retransmit;
    private DateTime _nextSend;
    private DateTime _retryAt;
    private int _tries;

    private byte[]? _serverDuid;
    private Dhcp6Prefix? _prefix;
    private Dhcp6Prefix? _offered;
    private DateTime _preferredUntil;
    private DateTime _validUntil;
    private DateTime _renewAt;
    private DateTime _rebindAt;
    private uint _solMaxRt = 3600;

    public PdClient(byte[] duid, uint iaid, byte wantLength, Func<double>? random = null)
    {
        _duid = duid;
        _iaid = iaid;
        _wantLength = wantLength;
        _random = random ?? (() => Random.Shared.NextDouble());
    }

    public PdState State => _state;
    public Dhcp6Prefix? Prefix => _prefix;

    // §18.2.1: "The first Solicit message from the client on the interface SHOULD be delayed by a random
    // amount of time between 0 and SOL_MAX_DELAY." The delay lives here so the caller has one timer.
    public IReadOnlyList<PdStep> Start(DateTime now)
    {
        if (_state != PdState.Starting) return Array.Empty<PdStep>();
        BeginSolicit(now);
        return Array.Empty<PdStep>();
    }

    public IReadOnlyList<PdStep> Poll(DateTime now)
    {
        var steps = new List<PdStep>();
        switch (_state)
        {
            case PdState.Soliciting:
                if (now < _nextSend) break;
                if (_tries == 0)
                {
                    // §21.9 counts Elapsed Time from the start of the exchange, and §18.2.1's random
                    // delay is before the exchange begins.
                    _exchangeStart = now;
                    _tries = 1;
                    _nextSend = now + Scatter(SolTimeout);
                }
                else
                {
                    _retransmit = Min(_retransmit * 2, TimeSpan.FromSeconds(_solMaxRt));
                    _nextSend = now + Scatter(_retransmit);
                }
                steps.Add(new PdTransmit(BuildSolicit(now - _exchangeStart), "solicit"));
                break;

            case PdState.Requesting:
                if (now < _nextSend) break;
                if (_tries >= ReqMaxRc)
                {
                    Lose(steps, "no Reply after the Request retry count", now);
                    break;
                }
                _tries++;
                _retransmit = Min(_retransmit * 2, ReqMaxRt);
                _nextSend = now + Scatter(_retransmit);
                steps.Add(new PdTransmit(BuildRequest(now - _exchangeStart, _offered), "request retransmit"));
                break;

            case PdState.Bound:
                if (now >= _validUntil)
                {
                    Lose(steps, "the valid lifetime of the delegated prefix ran out", now);
                    break;
                }
                // T2 is checked first because it can be the earlier of the two: §14.2 lets the client pick
                // T1 when the server sends 0, and that pick can land past a server-chosen T2.
                if (now >= _rebindAt)
                {
                    _state = PdState.Rebinding;
                    NewExchange(now, RebTimeout);
                    _nextSend = now + Scatter(RebTimeout);
                    steps.Add(new PdTransmit(BuildRebind(TimeSpan.Zero), "rebind at T2"));
                    break;
                }
                if (now >= _renewAt)
                {
                    _state = PdState.Renewing;
                    NewExchange(now, RenTimeout);
                    _nextSend = now + Scatter(RenTimeout);
                    steps.Add(new PdTransmit(BuildRenew(TimeSpan.Zero), "renew at T1"));
                }
                break;

            case PdState.Renewing:
                if (now >= _validUntil)
                {
                    Lose(steps, "the valid lifetime ran out while renewing", now);
                    break;
                }
                if (now >= _rebindAt)
                {
                    // §18.2.5: at T2 the Renew exchange is over and a Rebind goes out to any server.
                    _state = PdState.Rebinding;
                    NewExchange(now, RebTimeout);
                    _nextSend = now + Scatter(RebTimeout);
                    steps.Add(new PdTransmit(BuildRebind(TimeSpan.Zero), "rebind at T2"));
                    break;
                }
                if (now >= _nextSend)
                {
                    _retransmit = Min(_retransmit * 2, RenMaxRt);
                    _nextSend = now + Scatter(_retransmit);
                    steps.Add(new PdTransmit(BuildRenew(now - _exchangeStart), "renew retransmit"));
                }
                break;

            case PdState.Rebinding:
                if (now >= _validUntil)
                {
                    Lose(steps, "the valid lifetime ran out while rebinding", now);
                    break;
                }
                if (now >= _nextSend)
                {
                    _retransmit = Min(_retransmit * 2, RebMaxRt);
                    _nextSend = now + Scatter(_retransmit);
                    steps.Add(new PdTransmit(BuildRebind(now - _exchangeStart), "rebind retransmit"));
                }
                break;

            case PdState.Failed:
                if (now >= _retryAt) BeginSolicit(now);
                break;
        }
        return steps;
    }

    public IReadOnlyList<PdStep> Receive(byte[] datagram, IPAddress from, DateTime now)
    {
        var steps = new List<PdStep>();
        if (!Dhcp6Message.TryParse(datagram, out var message, out _)) return steps;
        if (message!.First(Dhcp6.OptClientId) is not { } clientId || !clientId.Data.AsSpan().SequenceEqual(_duid))
        {
            // §16.3 and §16.10: an Advertise or Reply whose Client Identifier is missing or is not this
            // client's DUID is discarded.
            return steps;
        }
        if (message.TransactionId != _transactionId) return steps;

        if (_state == PdState.Soliciting && message.Kind == Dhcp6Kind.Advertise)
        {
            if (message.First(Dhcp6.OptServerId) is not { } serverId) return steps;
            NoteSolMaxRt(message);
            // §18.2.2: the Request names the chosen server and repeats the offered prefix.
            _serverDuid = serverId.Data;
            _prefix = null;
            _offered = null;
            if (message.First(Dhcp6.OptIaPd)?.Data is { } advertised
                && Dhcp6.TryParseIapd(advertised, out _, out _, out _, out var advertisedPrefix, out _, out _))
            {
                _offered = advertisedPrefix?.Prefix;
            }
            _state = PdState.Requesting;
            NewExchange(now, ReqTimeout);
            _nextSend = now + Scatter(ReqTimeout);
            steps.Add(new PdTransmit(BuildRequest(TimeSpan.Zero, _offered), $"request after advertise from {from}"));
            return steps;
        }

        if (message.Kind != Dhcp6Kind.Reply) return steps;
        // A Reply is only an answer to an exchange that is open: one that arrives after the prefix was
        // released or withdrawn would otherwise re-bind a client that is tearing down.
        if (_state is not (PdState.Requesting or PdState.Renewing or PdState.Rebinding)) return steps;
        if (message.First(Dhcp6.OptServerId) is not { } replyServer) return steps;
        // §16.10 does not require the Reply's server to be the one the Request named - a Rebind is answered
        // by whichever server still knows the binding - so the reply's server becomes the current one.
        _serverDuid = replyServer.Data;
        NoteSolMaxRt(message);

        if (message.First(Dhcp6.OptIaPd) is not { } iaPd)
        {
            Lose(steps, $"the Reply from {from} carried no IA_PD ({message.Describe()})", now);
            return steps;
        }
        if (!Dhcp6.TryParseIapd(iaPd.Data, out _, out var t1, out var t2, out var granted, out var status, out var why))
        {
            Lose(steps, $"the Reply's IA_PD does not parse: {why}", now);
            return steps;
        }
        if (status == Dhcp6.StatusNoPrefixAvail)
        {
            Lose(steps, "the server answered NoPrefixAvail", now);
            return steps;
        }
        if (granted is not { } offer || offer.Prefix.IsZero)
        {
            Lose(steps, $"the Reply's IA_PD carried no prefix ({message.Describe()})", now);
            return steps;
        }

        var prefix = offer.Prefix.Masked();
        if (prefix.Length > 64)
        {
            Lose(steps, $"{prefix} is longer than /64, so no LAN client can form an address from it", now);
            return steps;
        }

        // §21.21: "If a client receives an IA_PD with T1 greater than T2 and both T1 and T2 are greater
        // than 0, the client discards the IA_PD option and processes the remainder of the message as
        // though the server had not included the IA_PD option."
        if (t1 > t2 && t1 > 0 && t2 > 0)
        {
            Lose(steps, $"the IA_PD sets T1 ({t1}s) later than T2 ({t2}s), so it is discarded (RFC 8415 §21.21)", now);
            return steps;
        }

        var preferred = Seconds(offer.Preferred);
        var valid = Seconds(offer.Valid);
        var wasBound = _state is PdState.Bound or PdState.Renewing or PdState.Rebinding;
        if (_prefix is { } previous && !previous.SameAs(prefix))
            steps.Add(new PdWithdrawn(previous, $"the server delegated {prefix} instead"));

        _prefix = prefix;
        _offered = null;
        _preferredUntil = Deadline(now, offer.Preferred);
        _validUntil = Deadline(now, offer.Valid);
        // §14.2: when either value is 0 the choice is the client's, so long as it avoids a storm. Half and
        // four fifths of the preferred lifetime are §21.21's recommended values for a server, reused for
        // that choice; T1 is held to T2 so a client-chosen T1 cannot postpone the rebind.
        _renewAt = t1 == 0 ? now + preferred / 2 : Deadline(now, t1);
        _rebindAt = t2 == 0 ? now + preferred * 0.8 : Deadline(now, t2);
        if (_renewAt > _rebindAt) _renewAt = _rebindAt;
        _state = PdState.Bound;
        _tries = 0;
        steps.Add(new PdDelegated(prefix, preferred, valid, from.ToString(), DnsServers(message),
            wasBound ? "renewed" : "delegated"));
        return steps;
    }

    // RFC 3646 §3: the option is a list of 16-octet addresses and "must be a multiple of 16". Only whole
    // addresses are taken, so a truncated tail names no server rather than a wrong one.
    private static IReadOnlyList<byte[]> DnsServers(Dhcp6Message message)
    {
        var servers = new List<byte[]>();
        if (message.First(Dhcp6.OptDnsServers)?.Data is not { } data) return servers;
        for (var offset = 0; offset + 16 <= data.Length; offset += 16)
            servers.Add(data.AsSpan(offset, 16).ToArray());
        return servers;
    }

    public IReadOnlyList<PdStep> Release(DateTime now)
    {
        var steps = new List<PdStep>();
        if (_state is not (PdState.Bound or PdState.Renewing or PdState.Rebinding)) return steps;
        if (_serverDuid is null || _prefix is not { } prefix) return steps;
        // §18.2.7: "For a delegated prefix, this means the prefix MUST have been advertised with a
        // Preferred Lifetime and a Valid Lifetime of 0 ... [before] the client begins the Release message
        // exchange process." The withdrawal therefore precedes the datagram.
        steps.Add(new PdWithdrawn(prefix, "released"));
        _state = PdState.Released;
        _prefix = null;
        _offered = null;
        var options = new List<Dhcp6Option>
        {
            new(Dhcp6.OptClientId, _duid),
            new(Dhcp6.OptServerId, _serverDuid),
            new(Dhcp6.OptElapsedTime, Dhcp6Elapsed(now - _exchangeStart)),
            new(Dhcp6.OptIaPd, Dhcp6.Iapd(_iaid, 0, 0,
                new Dhcp6Option(Dhcp6.OptIaPrefix, Dhcp6.IaPrefix(0, 0, prefix.Length, prefix.Address)))),
        };
        steps.Add(new PdTransmit(new Dhcp6Message(Dhcp6Kind.Release, NewTransactionId(), options).Build(),
            $"release {prefix}"));
        return steps;
    }

    private void BeginSolicit(DateTime now)
    {
        _state = PdState.Soliciting;
        _transactionId = NewTransactionId();
        _exchangeStart = now;
        _tries = 0;
        _retransmit = SolTimeout;
        _prefix = null;
        _nextSend = now + SolMaxDelay * _random();
    }

    private void NewExchange(DateTime now, TimeSpan timeout)
    {
        _transactionId = NewTransactionId();
        _exchangeStart = now;
        _tries = 1;
        _retransmit = timeout;
    }

    private void NoteSolMaxRt(Dhcp6Message message)
    {
        // §21.24: a client MUST ignore values below 60 or above 86400, and MUST adopt a valid one.
        if (message.First(Dhcp6.OptSolMaxRt) is not { Data.Length: 4 } option) return;
        var value = BinaryPrimitives.ReadUInt32BigEndian(option.Data);
        if (value is >= 60 and <= 86400) _solMaxRt = value;
    }

    private byte[] BuildSolicit(TimeSpan elapsed)
    {
        var options = new List<Dhcp6Option>
        {
            new(Dhcp6.OptClientId, _duid),
            new(Dhcp6.OptElapsedTime, Dhcp6Elapsed(elapsed)),
            new(Dhcp6.OptIaPd, Hint(_wantLength)),
            new(Dhcp6.OptOro, Oro()),
        };
        return new Dhcp6Message(Dhcp6Kind.Solicit, _transactionId, options).Build();
    }

    private byte[] BuildRequest(TimeSpan elapsed, Dhcp6Prefix? offered)
    {
        var options = new List<Dhcp6Option>
        {
            new(Dhcp6.OptClientId, _duid),
            new(Dhcp6.OptServerId, _serverDuid!),
            new(Dhcp6.OptElapsedTime, Dhcp6Elapsed(elapsed)),
            new(Dhcp6.OptIaPd, offered is { } echoed
                ? Dhcp6.Iapd(_iaid, 0, 0, new Dhcp6Option(Dhcp6.OptIaPrefix,
                    Dhcp6.IaPrefix(0, 0, echoed.Length, echoed.Address)))
                : Hint(_wantLength)),
            new(Dhcp6.OptOro, Oro()),
        };
        return new Dhcp6Message(Dhcp6Kind.Request, _transactionId, options).Build();
    }

    private byte[] BuildRenew(TimeSpan elapsed)
    {
        var options = new List<Dhcp6Option>
        {
            new(Dhcp6.OptClientId, _duid),
            new(Dhcp6.OptServerId, _serverDuid!),
            new(Dhcp6.OptElapsedTime, Dhcp6Elapsed(elapsed)),
            new(Dhcp6.OptIaPd, BoundIaPd()),
            new(Dhcp6.OptOro, Oro()),
        };
        return new Dhcp6Message(Dhcp6Kind.Renew, _transactionId, options).Build();
    }

    private byte[] BuildRebind(TimeSpan elapsed)
    {
        // §18.2.5: the Rebind differs from a Renew in its type and in carrying no Server Identifier.
        var options = new List<Dhcp6Option>
        {
            new(Dhcp6.OptClientId, _duid),
            new(Dhcp6.OptElapsedTime, Dhcp6Elapsed(elapsed)),
            new(Dhcp6.OptIaPd, BoundIaPd()),
            new(Dhcp6.OptOro, Oro()),
        };
        return new Dhcp6Message(Dhcp6Kind.Rebind, _transactionId, options).Build();
    }

    private byte[] Hint(byte length) => Dhcp6.Iapd(_iaid, 0, 0,
        new Dhcp6Option(Dhcp6.OptIaPrefix, Dhcp6.IaPrefix(0, 0, length, Dhcp6Prefix.ZeroAddress())));

    private byte[] BoundIaPd()
    {
        var prefix = _prefix!.Value;
        return Dhcp6.Iapd(_iaid, 0, 0,
            new Dhcp6Option(Dhcp6.OptIaPrefix, Dhcp6.IaPrefix(0, 0, prefix.Length, prefix.Address)));
    }

    // §18.2.1 and §18.2.2 both require an Option Request option and both name SOL_MAX_RT as one of the
    // codes it has to carry; the resolver address is asked for so the WAN's DNS is visible in the log.
    private static byte[] Oro() => new[]
    {
        (byte)0, (byte)Dhcp6.OptSolMaxRt, (byte)0, (byte)Dhcp6.OptDnsServers,
    };

    // §15.1: RAND is uniform in [-0.1, +0.1] and multiplies the value being timed.
    private TimeSpan Scatter(TimeSpan value)
    {
        var factor = 1.0 + (_random() * 0.2 - 0.1);
        var scattered = value * factor;
        return scattered < TimeSpan.FromMilliseconds(100) ? TimeSpan.FromMilliseconds(100) : scattered;
    }

    private static TimeSpan Min(TimeSpan left, TimeSpan right) => left < right ? left : right;

    private static TimeSpan Seconds(uint value) => value == Dhcp6.Infinity
        ? TimeSpan.MaxValue - TimeSpan.FromDays(1)
        : TimeSpan.FromSeconds(value);

    private static DateTime Deadline(DateTime now, uint value)
    {
        if (value == Dhcp6.Infinity) return DateTime.MaxValue;
        var span = TimeSpan.FromSeconds(value);
        return now + (span > DateTime.MaxValue - now ? DateTime.MaxValue - now : span);
    }

    private static byte[] Dhcp6Elapsed(TimeSpan elapsed)
    {
        // §21.9: a 16-bit count of hundredths of a second since the exchange began.
        var hundredths = (uint)Math.Clamp(elapsed.TotalSeconds * 100, 0, ushort.MaxValue);
        return new[] { (byte)(hundredths >> 8), (byte)hundredths };
    }

    private static uint NewTransactionId() => (uint)Random.Shared.Next(0, 1 << 24);

    private void Lose(List<PdStep> steps, string why, DateTime now)
    {
        steps.Add(new PdWithdrawn(_prefix, why));
        _prefix = null;
        _offered = null;
        _state = PdState.Failed;
        _retryAt = now + RetryAfterLoss;
    }
}
