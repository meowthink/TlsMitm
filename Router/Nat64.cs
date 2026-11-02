using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using TlsMitm;

namespace Router;

/// What this table decided about one packet. Translate hands back a new datagram for the caller to put on the
/// wire; Discard says the buffer must not go back at all; None leaves the packet on the path it was already
/// on, which is how traffic that is not the NAT64's keeps being forwarded by the host.
public enum Nat64Action { None, Translate, Discard }

public readonly record struct Nat64Outcome(Nat64Action Action, byte[]? Packet = null, string? Reason = null)
{
    public static readonly Nat64Outcome None = new(Nat64Action.None);
}

/// RFC 6146's stateful NAT64: the three Binding Information Bases and the session tables of §3.1-§3.2, and the
/// five steps of §3.3 - determine the incoming tuple (§3.4), filter and update the tables (§3.5), compute the
/// outgoing tuple (§3.6), translate the packet (§3.7), handle hairpinning (§3.8). §3.7 names the IP/ICMP
/// translation algorithm as its own base, so every header rewrite here is delegated to <see cref="Siit"/>,
/// which is that algorithm; what this class owns is the state that says which addresses and ports a flow's pair
/// came from.
///
/// Like NatTable, stateless about sockets and about WinDivert: one packet in, one packet out, an injectable
/// clock, so tests/nat64check exercises every rule with no driver and no admin.
///
/// One scope line runs through the file: this table rewrites packets that arrive, it never originates one.
/// Every place §3.4, §3.5.1, §3.5.1.1, §3.5.2.2 and §3.5.3 offer an ICMP error or a TCP probe ("if the security
/// policy permits", "MAY be sent", "SHOULD send a probe packet") is therefore the policy branch that does not
/// send, and each of those sites says so where the packet stops. The counters are what makes the difference
/// attributable: a discarded error is not a lost one.
public sealed class Nat64
{
    private const byte IcmpProto = 1;
    private const byte TcpProto = 6;
    private const byte UdpProto = 17;
    private const byte Icmpv6Proto = 58;

    private const byte Syn = 0x02;
    private const byte Fin = 0x01;
    private const byte Rst = 0x04;

    // §4's Protocol Constants. TCP_EST is the 2 hours §4 gives, and its own note there is that the 2 hours and 4
    // minutes RFC 5382's floor asks for "is achieved by adding the 2 hours with this timer and the 4 minutes with
    // the TCP_TRANS timer" - so an established session is armed with TCP_EST and TCP_TRANS is what an entry falls
    // back to when it stops being one. TCP_INCOMING_SYN has no constant here because the state it belongs to is
    // the one §3.5.2's policy branch removes.
    public static readonly TimeSpan UdpDefault = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan UdpMin = TimeSpan.FromMinutes(2);
    public static readonly TimeSpan TcpEstablished = TimeSpan.FromMinutes(124);
    public static readonly TimeSpan TcpTransitory = TimeSpan.FromMinutes(4);
    public static readonly TimeSpan IcmpQueryLifetime = TimeSpan.FromSeconds(60);

    // §3.4's fragment conditions: "the NAT64 MUST allow the fragments to arrive over a time interval ... the
    // default value MUST be of at least FRAGMENT_MIN", and FRAGMENT_MIN is 2 seconds. This is that interval,
    // widened; the ceiling behind it is the same paragraph's first bullet, which asks that the resources devoted
    // to fragmented packets be limited to protect from DoS attacks.
    public static readonly TimeSpan FragmentWindow = TimeSpan.FromSeconds(60);
    public const int FragmentCeiling = 4096;

    // The lowest port this table binds to. §3.5.1.1 prefers the client's own port and failing that a port in the
    // same range, §3.5.2.3 says the same for TCP, and both leave the choice of range to the implementer where
    // none is free ("the NAT64 MAY assign a port t from another range where it has an available port"). The range
    // here is the one the reply leg can see: Program.cs's filter recognises the answer to one of our flows by
    // its destination port being at or above this figure, so a binding below it would have that answer taken by
    // the local stack instead - which is the failure a §3.5.1.1 preference cannot be allowed to cause.
    public const ushort PortFirst = 49152;

    private readonly Pref64Config _prefix;
    private readonly Func<DateTime> _now;
    private readonly TimeSpan _udpLifetime;
    // Ports this host already holds, and the ones the same host's IPv4 NAT has bound. The mapped port is the
    // whole reverse key, so a flow bound to a port something else answers on has that something else's traffic
    // delivered to it instead.
    private readonly Func<byte, ICollection<ushort>>? _localPorts;
    private readonly Func<byte, ICollection<ushort>>? _otherMapped;

    private readonly ConcurrentDictionary<BibKey, Bib> _bibs = new();
    private readonly ConcurrentDictionary<ReverseKey, BibKey> _reverse = new();
    private readonly ConcurrentDictionary<SteKey, Ste> _sessions = new();
    private readonly ConcurrentDictionary<FragKey, FragMap> _fragments = new();
    private readonly object _alloc = new();
    private readonly FragmentIdentification _identification = new();
    private int _cursor;
    private volatile IPAddress _wanAddress;

    public long Bindings;
    public long Sessions;
    public long Translated64;
    public long Translated46;
    public long Hairpins;
    public long NoBinding;
    public long Filtered;
    public long Exhausted;
    public long FragmentReuses;
    public long FragmentRefused;

    public Nat64(Pref64Config prefix, IPAddress wanAddress, Func<DateTime>? now = null,
        TimeSpan? udpLifetime = null, Func<byte, ICollection<ushort>>? localPorts = null,
        Func<byte, ICollection<ushort>>? otherMapped = null)
    {
        _prefix = prefix;
        _wanAddress = wanAddress;
        _now = now ?? (() => DateTime.UtcNow);
        _localPorts = localPorts;
        _otherMapped = otherMapped;
        var asked = udpLifetime ?? UdpDefault;
        if (asked < UdpMin)
            throw new ArgumentOutOfRangeException(nameof(udpLifetime),
                $"§3.5.1: \"The maximum session lifetime MUST NOT be less than UDP_MIN\", {UdpMin.TotalSeconds:0} seconds");
        _udpLifetime = asked;
    }

    public IPAddress WanAddress => _wanAddress;

    /// A lease renewal moves the address the whole table binds to. Nothing keys on it: the reverse lookup is the
    /// mapped port alone, which is §5.2's Endpoint-Independent Mapping, so the bindings stay valid and the next
    /// packet is written with the new source. The flows a peer already saw under the old one break at the peer,
    /// so they are left to their own timers rather than flushed.
    public void SetWanAddress(IPAddress address) => _wanAddress = address;

    public int BindingCount => _bibs.Count;
    public int SessionCount => _sessions.Count;
    public int FragmentRecordCount => _fragments.Count;

    /// Whether a transport identifier on this table's own IPv4 address is one it bound. Program.cs's reply
    /// dispatch asks it before the IPv4 NAT sees the packet, and each allocator asks the other's view through
    /// <see cref="_otherMapped"/> so the two never bind the same one.
    public bool IsMappedPort(byte proto, ushort port) => _reverse.ContainsKey(new ReverseKey(proto, port));

    public ICollection<ushort> MappedPorts(byte proto)
    {
        var ports = new List<ushort>();
        foreach (var key in _reverse.Keys)
            if (key.Proto == proto) ports.Add(key.Mapped);
        return ports;
    }

    // The test of whether a packet is this table's to answer for, run before the IPv4 NAT is asked. It is the
    // same reverse key the reply leg would use, read off the arriving packet: the destination port for TCP and
    // UDP, the Identifier for an ICMP query, and for an ICMP error the source port of the packet quoted inside
    // it - which is the one this translator wrote on the way out.
    public bool OwnsDatagram(ReadOnlySpan<byte> packet)
    {
        if (!Siit.TryReadV4(packet, false, out var head, out _) ||
            !Address(packet, 16, AddressFamily.InterNetwork).Equals(_wanAddress)) return false;
        // A fragment other than the first carries no transport header at all, so the reverse key it would need is
        // not in the packet. §3.4's third fragment bullet is the option this reads: the NAT64 "MAY translate the
        // fragments as they arrive, by storing information that allows it to compute the 5-tuple for fragments
        // other than the first", and the record the first one left behind is that information.
        if (head.FragmentOffset != 0)
            return _fragments.ContainsKey(new FragKey(head.Protocol,
                Address(packet, 12, AddressFamily.InterNetwork), _wanAddress, head.Identification));
        var body = packet.Slice(head.Transport, head.DatagramEnd - head.Transport);
        if (head.Protocol is TcpProto or UdpProto)
            return body.Length >= 4 && IsMappedPort(head.Protocol, BinaryPrimitives.ReadUInt16BigEndian(body.Slice(2, 2)));
        if (head.Protocol != IcmpProto || body.Length < 8) return false;
        if (IsIcmp4Error(body))
        {
            if (!TryEmbedded(packet, head, out var inner, out var quoted, out _) ||
                !Address(inner, 12, AddressFamily.InterNetwork).Equals(_wanAddress)) return false;
            // The same two tuples IcmpError46 reads: the quoted TCP or UDP packet's source port, which is the one
            // this table wrote on the way out, or the Identifier of the query it quotes.
            if (quoted.Protocol is TcpProto or UdpProto)
                return inner.Length >= quoted.Transport + 4 &&
                       IsMappedPort(quoted.Protocol,
                           BinaryPrimitives.ReadUInt16BigEndian(inner.Slice(quoted.Transport)[..2]));
            return quoted.Protocol == IcmpProto && inner.Length >= quoted.Transport + 8 &&
                   IsMappedPort(IcmpProto,
                       BinaryPrimitives.ReadUInt16BigEndian(inner.Slice(quoted.Transport + 4)[..2]));
        }
        return IsMappedPort(IcmpProto, BinaryPrimitives.ReadUInt16BigEndian(body.Slice(4, 2)));
    }

    // --- §3.3's five steps ---------------------------------------------------------------------------------------------

    public Nat64Outcome Translate(ReadOnlySpan<byte> packet, Siit.PathMtu path)
    {
        var version = packet.Length > 0 ? packet[0] >> 4 : 0;
        return version switch
        {
            6 => FromIpv6(packet, path, hairpin: false),
            4 => FromIpv4(packet, path, hairpin: false),
            _ => Nat64Outcome.None,
        };
    }

    private Nat64Outcome FromIpv6(ReadOnlySpan<byte> packet, Siit.PathMtu path, bool hairpin)
    {
        if (!Siit.TryReadV6(packet, false, out var head, out _)) return Nat64Outcome.None;
        var source = Address(packet, 8, AddressFamily.InterNetworkV6);
        var destination = Address(packet, 24, AddressFamily.InterNetworkV6);

        // §3.5's rules hold whatever the transport is. A source inside the prefix is a packet this translator
        // already sent, and §5 counts processing it again as the hairpinning loop the rule exists to prevent.
        if (Pref64.Extract(_prefix.Prefix, _prefix.PrefixLength, source) is not null)
        {
            Interlocked.Increment(ref Filtered);
            return new Nat64Outcome(Nat64Action.Discard, null,
                "§3.5: \"the NAT64 MUST silently discard all incoming IPv6 packets containing a source address that " +
                "contains the Pref64::/n\"");
        }
        // And a destination outside the prefix is not this table's business. That is the clause that leaves an
        // ICMPv6 error on the host's forwarding path: §3.4 makes a message about a packet the client sent a
        // reply to the client, so its destination is the client's own address, and the client's stack is the one
        // that wants the Path MTU or the Unreachable inside it.
        var peer = Pref64.Extract(_prefix.Prefix, _prefix.PrefixLength, destination);
        if (peer is null) return Nat64Outcome.None;

        var protocol = head.Protocol;
        if (protocol is not (TcpProto or UdpProto or Icmpv6Proto))
        {
            Interlocked.Increment(ref NoBinding);
            return new Nat64Outcome(Nat64Action.Discard, null,
                $"§3.4: an IPv6 packet whose last Next Header is {protocol}, not TCP, UDP or ICMPv6, \"SHOULD be " +
                "discarded\" - with an ICMPv6 Destination Unreachable Code 4 only \"if the security policy permits\", " +
                "and this translator originates no message of its own");
        }
        if (protocol == Icmpv6Proto) return IcmpQuery64(packet, head, source, destination, peer, path, hairpin);
        if (head.FragmentOffset != 0) return ReplayFragment64(packet, head, protocol, path);

        var transport = packet.Slice(head.Transport, head.DatagramEnd - head.Transport);
        if (transport.Length < 4)
            return new Nat64Outcome(Nat64Action.Discard, null,
                "§3.4: the third fragment bullet lets a NAT64 \"require that the UDP, TCP, or ICMP header be " +
                $"completely contained within the fragment that contains fragment offset equal to zero\", and {transport.Length} octets do not");
        var ports = ReadPorts(transport);
        return protocol == UdpProto
            ? Udp64(packet, head, source, ports.Source, destination, ports.Destination, peer, path, hairpin)
            : Tcp64(packet, head, source, ports.Source, destination, ports.Destination, peer, path, hairpin);
    }

    private Nat64Outcome FromIpv4(ReadOnlySpan<byte> packet, Siit.PathMtu path, bool hairpin)
    {
        if (!Siit.TryReadV4(packet, false, out var head, out _)) return Nat64Outcome.None;
        var source = Address(packet, 12, AddressFamily.InterNetwork);
        var destination = Address(packet, 16, AddressFamily.InterNetwork);

        // §3.5: "the NAT64 MUST only process incoming IPv4 packets that contain a destination address that
        // belongs to the IPv4 pool assigned to the NAT64". The pool is the one address of the interface, and what
        // reaches it is the answer to a flow this table sent plus whatever this host's own stack wants.
        if (!destination.Equals(_wanAddress)) return Nat64Outcome.None;

        var protocol = head.Protocol;
        if (protocol is not (TcpProto or UdpProto or IcmpProto))
        {
            Interlocked.Increment(ref NoBinding);
            return new Nat64Outcome(Nat64Action.Discard, null,
                $"§3.4: an IPv4 packet whose Protocol is {protocol}, not TCP, UDP or ICMPv4, \"SHOULD be discarded\" " +
                "with an ICMPv4 Code 2 only \"if the security policy permits\"");
        }
        var transport = packet.Slice(head.Transport, head.DatagramEnd - head.Transport);
        if (protocol == IcmpProto)
        {
            if (transport.Length < 8) return Nat64Outcome.None;
            if (IsIcmp4Error(transport)) return IcmpError46(packet, head, path);
            return IcmpQuery46(packet, head, source, transport, path, hairpin);
        }

        if (head.FragmentOffset != 0) return ReplayFragment46(packet, head, protocol, path);
        if (transport.Length < 4)
            return new Nat64Outcome(Nat64Action.Discard, null,
                "§3.4: the third fragment bullet lets a NAT64 \"require that the UDP, TCP, or ICMP header be " +
                "completely contained within the fragment that contains fragment offset equal to zero\"");
        var ports = ReadPorts(transport);
        return protocol == UdpProto
            ? Udp46(packet, head, source, ports.Source, ports.Destination, path, hairpin)
            : Tcp46(packet, head, source, ports.Source, ports.Destination, path, hairpin);
    }

    // --- §3.5.1's UDP --------------------------------------------------------------------------------------------------

    private Nat64Outcome Udp64(ReadOnlySpan<byte> packet, Siit.V6Header head, IPAddress source, ushort x,
        IPAddress destination, ushort y, IPAddress peer, Siit.PathMtu path, bool hairpin)
    {
        var binding = BindingFor(new BibKey(UdpProto, source, x));
        if (binding.MappedPort is null) return NoAllocation();

        // §3.5.1's five bullets: the session's IPv6 pair comes from the packet, its source IPv4 pair from the
        // binding, and its destination IPv4 pair is the peer address with the same port y - which is §3.2's
        // "the STE destination IPv4 port is set to y, i.e. the same port as the STE destination IPv6 transport
        // address" made readable as the invariant the reply leg relies on.
        var ste = Session(new SteKey(UdpProto, source, x, destination, y), binding, peer, _now() + _udpLifetime);
        var outcome = ToV4(Rewritten64(packet, head, binding), protocol: UdpProto, binding, ste, path, hairpin);
        if (head is { Fragmented: true, FragmentOffset: 0 }) RecordFragment(head.Protocol, source, destination, head.Identification, binding);
        return outcome;
    }

    private Nat64Outcome Udp46(ReadOnlySpan<byte> packet, Siit.V4Header head, IPAddress source /*W*/, ushort w,
        ushort t, Siit.PathMtu path, bool hairpin)
    {
        if (!_reverse.TryGetValue(new ReverseKey(UdpProto, t), out var bibKey) || !_bibs.TryGetValue(bibKey, out var binding))
        {
            Interlocked.Increment(ref NoBinding);
            return new Nat64Outcome(Nat64Action.Discard, null,
                "§3.5.1: an IPv4 packet whose destination transport address has no UDP BIB entry \"MUST be dropped\" " +
                "- the Type 3 error the same paragraph permits is the branch this translator does not take");
        }
        // §3.5.1's two searches are different: the filter compares the destination IPv4 *address* of a session of
        // this binding with the packet's source, and the entry that carries the translation is keyed by the full
        // transport address. A reply from the same host on a new port therefore passes the filter and gets its own
        // session, which is §3.5.1's new-entry branch, while a reply from a host the client never reached is
        // discarded there.
        if (Allowed(binding, source) is null) return FilteringFailure();
        var ste = Session(new SteKey(UdpProto, bibKey.V6, bibKey.Port, Embed(source)!, w), binding, source, _now() + _udpLifetime);

        var bytes = packet.ToArray();
        RewritePorts(bytes.AsSpan(head.Transport), UdpProto, null, ste.Key.SourcePort);
        var outcome = ToV6(bytes, binding, path, hairpin);
        // The same record the IPv6 leg keeps: without it the second and later fragments of a fragmented answer
        // reach ReplayFragment46 with nothing to be read from.
        if (outcome.Action == Nat64Action.Translate && head is { Fragmented: true, FragmentOffset: 0 })
            RecordFragment(head.Protocol, source, _wanAddress, head.Identification, binding);
        return outcome;
    }

    // --- §3.5.2's TCP machine ------------------------------------------------------------------------------------------

    private Nat64Outcome Tcp64(ReadOnlySpan<byte> packet, Siit.V6Header head, IPAddress source, ushort x,
        IPAddress destination, ushort y, IPAddress peer, Siit.PathMtu path, bool hairpin)
    {
        var flags = packet.Length >= head.Transport + 14 ? packet[head.Transport + 13] : (byte)0;
        var syn = !head.Fragmented && (flags & Syn) != 0;
        var steKey = new SteKey(TcpProto, source, x, destination, y);
        var bibKey = new BibKey(TcpProto, source, x);

        Bib binding;
        Ste? ste = null;
        if (syn)
        {
            binding = BindingFor(bibKey);
            if (binding.MappedPort is null) return NoAllocation();
            // §3.5.2's CLOSED bullets 2 and 3 arm the new session at TCP_TRANS and move it to V6 INIT. A SYN on a
            // session that is already somewhere else is the retransmission V6 INIT keeps in place, and Advance is
            // what keeps it there.
            ste = Session(steKey, binding, peer, _now() + TcpTransitory, TcpState.V6Init);
            Advance(ste, flags, fromV6: true);
        }
        else if (_bibs.TryGetValue(bibKey, out var known))
        {
            // §3.5.2's CLOSED row for "any other packet belonging to this connection" asks about the BIB, not
            // about a session: with a binding the packet is translated and forwarded and "the state remains
            // unchanged", which for a 5-tuple that never had a session means it forwards without one. No binding
            // is created here, so a packet that is not a SYN cannot spend a port on a flow nothing can answer.
            binding = known;
            if (_sessions.TryGetValue(steKey, out ste))
            {
                if (!head.Fragmented) Advance(ste, flags, fromV6: true);
                else ste.Expires = _now() + LifetimeFor(ste.State);
            }
        }
        else
        {
            Interlocked.Increment(ref NoBinding);
            return new Nat64Outcome(Nat64Action.Discard, null,
                "§3.5.2: in CLOSED, \"If there is no corresponding entry in the TCP BIB, the packet is silently discarded\"");
        }

        var outcome = ToV4(Rewritten64(packet, head, binding), protocol: TcpProto, binding, ste, path, hairpin);
        if (outcome.Action == Nat64Action.Translate && head is { Fragmented: true, FragmentOffset: 0 })
            RecordFragment(head.Protocol, source, destination, head.Identification, binding);
        return outcome;
    }

    private Nat64Outcome Tcp46(ReadOnlySpan<byte> packet, Siit.V4Header head, IPAddress source /*Y*/, ushort w /*y*/,
        ushort t, Siit.PathMtu path, bool hairpin)
    {
        if (!_reverse.TryGetValue(new ReverseKey(TcpProto, t), out var bibKey) || !_bibs.TryGetValue(bibKey, out var binding))
        {
            Interlocked.Increment(ref NoBinding);
            return new Nat64Outcome(Nat64Action.Discard, null,
                "§3.5.2: \"If the security policy requires silently dropping externally initiated TCP connections, " +
                "then the packet is silently discarded\" - the policy this translator runs, so there is no V4 INIT " +
                "state, no stored SYN and no TCP_INCOMING_SYN timer");
        }
        var ste = Allowed(binding, source);
        if (ste is null) return FilteringFailure();

        var flags = packet.Length >= head.Transport + 14 ? packet[head.Transport + 13] : (byte)0;
        if (!head.Fragmented) Advance(ste, flags, fromV6: false);
        else ste.Expires = _now() + LifetimeFor(ste.State);

        var bytes = packet.ToArray();
        RewritePorts(bytes.AsSpan(head.Transport), TcpProto, null, ste.Key.SourcePort);
        var outcome = ToV6(bytes, binding, path, hairpin);
        if (outcome.Action == Nat64Action.Translate && head is { Fragmented: true, FragmentOffset: 0 })
            RecordFragment(head.Protocol, source, _wanAddress, head.Identification, binding);
        return outcome;
    }

    // §3.5.2.2's machine with V4 INIT removed: the states one IPv6-initiated connection passes through, and the
    // events the two legs deliver to them. Only the rows the section writes are here - V6 INIT keeps its state
    // against a retransmitted SYN, BothFinRcv has no way back out because its only exit is the expiry, and a RST
    // moves ESTABLISHED to TRANS because the section says the NAT64 "is uncertain whether the peer will accept
    // the RST packet" and so gives it the short timer instead of the state machine's end.
    private void Advance(Ste ste, byte flags, bool fromV6)
    {
        var syn = (flags & Syn) != 0;
        var fin = (flags & Fin) != 0;
        var rst = (flags & Rst) != 0;

        if (rst)
        {
            // Only ESTABLISHED has a RST row. In every other state the section's own words are "for any other
            // packet ... the state remains unchanged", which a RST is where no row names it.
            if (ste.State == TcpState.Established) ste.State = TcpState.Trans;
        }
        else if (syn && !fromV6 && ste.State == TcpState.V6Init) ste.State = TcpState.Established;
        else if (fin && ste.State == TcpState.Established) ste.State = fromV6 ? TcpState.V6FinRcv : TcpState.V4FinRcv;
        else if (fin && ste.State == (fromV6 ? TcpState.V4FinRcv : TcpState.V6FinRcv))
            // The other leg's FIN is the only one that closes the second half: V4 FIN RCV names "a V6 FIN packet"
            // and V6 FIN RCV names "a V4 FIN packet", and each state's next row is "any packet other than" that
            // one, so a second FIN from the leg already closed leaves the state where it is.
            ste.State = TcpState.BothFinRcv;
        else if (!rst && ste.State == TcpState.Trans) ste.State = TcpState.Established;

        ste.Expires = _now() + LifetimeFor(ste.State);
    }

    private static TimeSpan LifetimeFor(TcpState state) => state switch
    {
        // V6 INIT is armed with TCP_TRANS by §3.5.2's CLOSED bullet 2 and kept there by its own V6 SYN row.
        // TCP_TRANS is also what §3.5.2.2 names for TRANS and for V6 FIN + V4 FIN RCV. ESTABLISHED and the two
        // half-closed states are armed with the maximum session lifetime, which is what "at least TCP_EST" there
        // asks for, and 124 minutes is §4's own recipe for the 2 hours and 4 minutes RFC 5382's floor.
        TcpState.V6Init or TcpState.Trans or TcpState.BothFinRcv => TcpTransitory,
        _ => TcpEstablished,
    };

    // --- §3.5.3's ICMP queries -------------------------------------------------------------------------------------------

    private Nat64Outcome IcmpQuery64(ReadOnlySpan<byte> packet, Siit.V6Header head, IPAddress source,
        IPAddress destination, IPAddress peer, Siit.PathMtu path, bool hairpin)
    {
        var message = packet.Slice(head.Transport, head.DatagramEnd - head.Transport);
        if (head.Fragmented)
            return new Nat64Outcome(Nat64Action.Discard, null,
                "RFC 7915 §3: \"Fragmented ICMP/ICMPv6 packets will not be translated by IP/ICMP translators\", and " +
                "§3.4's 3-tuple needs the Identifier a later fragment does not carry");
        if (message.Length < 8) return Nat64Outcome.None;
        // §3.4's three error bullets read "the incoming IP packet" in either direction, so an ICMPv6 error is the
        // same step the IPv4 leg takes, not a message this table has no rule for.
        if (IsIcmp6Error(message)) return IcmpError64(packet, head, path);
        // §3.4's Query bullet names "an ICMPv6 Informational message", and §5.2's table keeps only its two Echo
        // rows: the MLD and Neighbor Discovery messages it shares the informational range with are "Single-hop
        // message. Silently drop." The gate runs before the allocation so a message that cannot be translated
        // spends neither an identifier nor a session.
        if (message[0] is not (128 or 129))
            return new Nat64Outcome(Nat64Action.Discard, null,
                $"§5.2: ICMPv6 type {message[0]} is not one of the table's two Echo rows, and its informational " +
                "message beside them is a \"Single-hop message. Silently drop\"");

        var i1 = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(4, 2));
        // §3.5.3's first bullet is a policy question - "If the local security policy determines that ICMPv6
        // Informational packets are to be filtered, the packet is silently discarded" - and this one does not
        // filter them, which is what lets ping6 across the translator reach a host with no IPv6 address.
        var binding = BindingFor(new BibKey(IcmpProto, source, i1));
        if (binding.MappedPort is null)
        {
            Interlocked.Increment(ref Exhausted);
            return new Nat64Outcome(Nat64Action.Discard, null,
                "§3.5.3: the binding is to be created with \"any available value ... as the BIB ICMPv4 Identifier, i.e. " +
                "any identifier value for which no other entry exists with the same (IPv4 address, ICMPv4 Identifier) " +
                "pair\", and none is available");
        }
        // The 3-tuple of §3.2's ICMP Query session, held in the same five slots as a TCP or UDP session: both
        // Identifier fields are i1, because the reply that has to find this session carries the identifier we put
        // on the wire back in its own Identifier field.
        var ste = Session(new SteKey(IcmpProto, source, i1, destination, i1), binding, peer, _now() + IcmpQueryLifetime);

        var bytes = packet.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(head.Transport + 4), binding.MappedPort.Value);
        return ToV4(bytes, protocol: Icmpv6Proto, binding, ste, path, hairpin);
    }

    private Nat64Outcome IcmpQuery46(ReadOnlySpan<byte> packet, Siit.V4Header head, IPAddress source /*Y*/,
        ReadOnlySpan<byte> message, Siit.PathMtu path, bool hairpin)
    {
        if (head.Fragmented)
            return new Nat64Outcome(Nat64Action.Discard, null,
                "RFC 7915 §3: \"Fragmented ICMP/ICMPv6 packets will not be translated by IP/ICMP translators\"");
        var i2 = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(4, 2));
        // The same gate as the IPv6 side, read from §4.2: the two Echo rows are the only Query messages the table
        // translates, and everything else that is not one of its three error rows - Redirect, Router Advertisement,
        // Timestamp, the rest - is a drop of §4.2's own listing. It cannot be allowed to reach the session table
        // through an identifier that happens to match one of ours.
        if (message[0] is not (0 or 8))
            return new Nat64Outcome(Nat64Action.Discard, null,
                $"§4.2: ICMPv4 type {message[0]} is not one of the table's two Echo rows; §3.4's Query bullet names " +
                "\"an ICMPv4 Query message\", and the messages beside it are ones §4.2 silently drops");
        if (!_reverse.TryGetValue(new ReverseKey(IcmpProto, i2), out var bibKey) || !_bibs.TryGetValue(bibKey, out var binding))
        {
            Interlocked.Increment(ref NoBinding);
            return new Nat64Outcome(Nat64Action.Discard, null,
                "§3.5.3: an ICMPv4 Query whose IPv4 address and Identifier have no ICMP Query BIB entry \"is dropped\" " +
                "- the Type 3 Code 1 the same paragraph permits is the branch this translator does not take");
        }
        // §3.5.3's filter and its entry both ask for a session whose source IPv4 address is X, whose ICMPv4
        // Identifier is i2 and whose destination IPv4 address is Y. The first two are already fixed by the binding
        // the lookup above found, because every session of an ICMP Query binding carries that binding's i2, which
        // leaves the peer address as the only part of the rule that can still fail.
        if (Allowed(binding, source) is null) return FilteringFailure();
        var ste = Session(new SteKey(IcmpProto, bibKey.V6, bibKey.Port, Embed(source)!, bibKey.Port), binding, source, _now() + IcmpQueryLifetime);

        var bytes = packet.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(head.Transport + 4), ste.Key.SourcePort);
        return ToV6(bytes, binding, path, hairpin);
    }

    // --- §3.4's error path ----------------------------------------------------------------------------------------------

    // The tuple comes from the embedded packet with its roles swapped (§3.4), which makes it the tuple of the
    // direction the error is travelling, and §3.6.1 reads it that way: the source is generated algorithmically
    // and the binding is searched for the destination. §3.5 keeps errors out of the tables altogether, so nothing
    // here is created and no timer is refreshed - which is RFC 5508's REQ-6 for the case, and §3.7's own rule
    // that the quoted packet's transport addresses become the outgoing tuple's destination and source, swapped.
    private Nat64Outcome IcmpError46(ReadOnlySpan<byte> packet, Siit.V4Header head, Siit.PathMtu path)
    {
        if (!TryEmbedded(packet, head, out var inner, out var quoted, out var why))
            return new Nat64Outcome(Nat64Action.Discard, null,
                $"§3.4: \"If it is not possible to determine the incoming 5-tuple ... the incoming IP packet MUST be silently discarded\" - {why}");
        if (!Address(inner, 12, AddressFamily.InterNetwork).Equals(_wanAddress))
            return new Nat64Outcome(Nat64Action.Discard, null,
                "§3.4: the quoted packet's source is not this NAT64's own IPv4 address, so the error is not about a " +
                "packet this translator forwarded");
        if (quoted.Protocol == IcmpProto)
        {
            // §3.4's third case: an error that quotes a Query is processed, and it is processed with the 3-tuple
            // the quote's own source, destination and Identifier give with the first two crossed. An error inside
            // an error is the bullet above it, silently discarded, and a message that is neither is one no tuple
            // can be read from - §4.2 has Echo and Echo Reply, and nothing else in ICMPv4 reaches a NAT64's query
            // table. The identifier is read where RFC 792 §1.9 puts it, four octets into the embedded message.
            if (inner.Length < quoted.Transport + 8)
                return new Nat64Outcome(Nat64Action.Discard, null,
                    "§3.4: \"If it is not possible to determine the incoming 3-tuple (perhaps because not enough of " +
                    "the embedded packet is reproduced inside the ICMP message), then the incoming IP packet MUST be " +
                    "silently discarded\" - the quote stops " + (inner.Length - quoted.Transport) + " octets into its message");
            if (IsIcmp4Error(inner.Slice(quoted.Transport)))
                return new Nat64Outcome(Nat64Action.Discard, null,
                    "§3.4: \"If the incoming IP packet contains a complete (un-fragmented) ICMP error message " +
                    "containing an ICMP error message, then the packet is silently discarded\"");
            if (inner[quoted.Transport] is not (0 or 8))
                return new Nat64Outcome(Nat64Action.Discard, null,
                    $"§3.4: the quoted ICMPv4 message is type {inner[quoted.Transport]}, neither one of its three " +
                    "error types nor one of §4.2's two Echo rows, so no incoming tuple can be read from it");
            var i2 = BinaryPrimitives.ReadUInt16BigEndian(inner.Slice(quoted.Transport + 4));
            if (!_reverse.TryGetValue(new ReverseKey(IcmpProto, i2), out var queryKey) ||
                !_bibs.TryGetValue(queryKey, out var query))
                return new Nat64Outcome(Nat64Action.Discard, null,
                    "§3.6.2: \"The BIB is searched for an entry containing (X',i1) <--> (D,i2), and, if found, the " +
                    $"outgoing destination address is X' and the outgoing ICMPv6 Identifier is i1\" - no binding owns identifier {i2}");
            // §3.7's third bullet reaches into the quote here: the Query's Identifier is set to the one from the
            // outgoing 3-tuple, which is the binding's own i1, and the outer message's checksum is what the
            // translation recomputes over it.
            var queryBytes = packet.ToArray();
            BinaryPrimitives.WriteUInt16BigEndian(
                queryBytes.AsSpan(head.Transport + 8 + quoted.Transport + 4), query.Key.Port);
            return ToV6(queryBytes, query, path, hairpin: false);
        }
        if (quoted.Protocol is not (TcpProto or UdpProto))
            return new Nat64Outcome(Nat64Action.Discard, null,
                $"§3.4: the quoted packet carries protocol {quoted.Protocol}, which is none of the TCP, UDP or ICMP " +
                "the section names, so no incoming tuple can be read from it");
        if (inner.Length < quoted.Transport + 4)
            return new Nat64Outcome(Nat64Action.Discard, null,
                "§3.4: the embedded packet stops before its transport ports, so the incoming tuple cannot be determined");

        var t = BinaryPrimitives.ReadUInt16BigEndian(inner.Slice(quoted.Transport)[..2]);
        if (!_reverse.TryGetValue(new ReverseKey(quoted.Protocol, t), out var bibKey) ||
            !_bibs.TryGetValue(bibKey, out var binding))
            return new Nat64Outcome(Nat64Action.Discard, null,
            "§3.6.1: the outgoing tuple is read from a binding that owns the quoted port - \"if the BIB contains an " +
            "entry (S',s) <--> (T,t)\" - and none does");

        // §3.7's last bullet, applied to the quote rather than to the message: the quoted source port becomes the
        // client's own, and its destination port already matches because §3.2 makes y and z the same figure.
        var bytes = packet.ToArray();
        RewritePorts(bytes.AsSpan(head.Transport + 8 + quoted.Transport), quoted.Protocol, binding.Key.Port, null);
        return ToV6(bytes, binding, path, hairpin: false);
    }

    // The IPv6 half of the same step, which §3.5 sends here in one sentence - "for the case of ICMP error
    // messages, they do not affect in any way either the BIBs or the session tables, so there is no processing
    // resulting from these messages in this section. ICMP error message processing continues in Section 3.6" - and
    // §3.6.1 then reads in this direction as the search of the BIB for (S',s) <--> (T,t): the tuple's source is the
    // quoted packet's destination, which names the client, so the binding is found by its own key rather than
    // through the reverse index the IPv4 leg has to use. Nothing here refreshes a timer or adds a session.
    private Nat64Outcome IcmpError64(ReadOnlySpan<byte> packet, Siit.V6Header head, Siit.PathMtu path)
    {
        if (!TryEmbedded64(packet, head, out var inner, out var quoted, out var why))
            return new Nat64Outcome(Nat64Action.Discard, null,
                $"§3.4: \"If it is not possible to determine the incoming 5-tuple ... the incoming IP packet MUST be silently discarded\" - {why}");
        if (quoted.Protocol == Icmpv6Proto)
        {
            if (inner.Length < quoted.Transport + 8)
                return new Nat64Outcome(Nat64Action.Discard, null,
                    "§3.4: \"If it is not possible to determine the incoming 3-tuple (perhaps because not enough of " +
                    "the embedded packet is reproduced inside the ICMP message), then the incoming IP packet MUST be " +
                    "silently discarded\" - the quote stops " + (inner.Length - quoted.Transport) + " octets into its message");
            if (IsIcmp6Error(inner[quoted.Transport..]))
                return new Nat64Outcome(Nat64Action.Discard, null,
                    "§3.4: \"If the incoming IP packet contains a complete (un-fragmented) ICMP error message " +
                    "containing an ICMP error message, then the packet is silently discarded\"");
            // §3.4's third bullet names the Query messages, and §5.2's table has exactly two of them for this
            // family: the Echo Request and the Echo Reply, which are also the only ICMPv6 informational messages
            // RFC 4443 §4.1 gives an Identifier field to.
            if (inner[quoted.Transport] is not (128 or 129))
                return new Nat64Outcome(Nat64Action.Discard, null,
                    $"§3.4: the quoted ICMPv6 message is type {inner[quoted.Transport]}, neither one of §5.2's two error " +
                    "rows nor one of its two Echo rows, so no incoming 3-tuple can be read from it");
            var i1 = BinaryPrimitives.ReadUInt16BigEndian(inner.Slice(quoted.Transport + 4)[..2]);
            if (!_bibs.TryGetValue(new BibKey(IcmpProto, Address(inner, 24, AddressFamily.InterNetworkV6), i1),
                    out var query))
                return new Nat64Outcome(Nat64Action.Discard, null,
                    "§3.6.2: \"the BIB contains an entry (S',i1) <--> (T,i2), then the outgoing source address is T " +
                    $"and the ICMPv4 Identifier is i2\" - no binding holds identifier {i1} for this client");
            // §3.7's third bullet reaches into the quote here: the Query's Identifier is set to the one from the
            // outgoing 3-tuple, which is the binding's mapped identifier, and the translation recomputes the
            // checksum of the message that carries it.
            var queryBytes = packet.ToArray();
            BinaryPrimitives.WriteUInt16BigEndian(
                queryBytes.AsSpan(head.Transport + 8 + quoted.Transport + 4), query.MappedPort!.Value);
            return ToV4(queryBytes, protocol: Icmpv6Proto, query, ste: null, path, hairpin: false);
        }
        if (quoted.Protocol is not (TcpProto or UdpProto))
            return new Nat64Outcome(Nat64Action.Discard, null,
                $"§3.4: the quoted packet carries protocol {quoted.Protocol}, which is none of the TCP, UDP or ICMP " +
                "the section names, so no incoming tuple can be read from it");
        if (inner.Length < quoted.Transport + 4)
            return new Nat64Outcome(Nat64Action.Discard, null,
                "§3.4: the embedded packet stops before its transport ports, so the incoming tuple cannot be determined");

        // The quoted packet's destination is the client, so its destination port is the tuple's source port s and
        // the BIB's own key finds the mapped pair. §3.7 then reaches into the quote once: the quoted destination
        // port becomes t, and the quoted source port already matches because §3.2 makes y and z the same figure.
        var s = BinaryPrimitives.ReadUInt16BigEndian(inner.Slice(quoted.Transport + 2)[..2]);
        if (!_bibs.TryGetValue(new BibKey(quoted.Protocol, Address(inner, 24, AddressFamily.InterNetworkV6), s),
                out var binding))
            return new Nat64Outcome(Nat64Action.Discard, null,
            "§3.6.1: the outgoing tuple is read from a binding that owns the quoted port - \"if the BIB contains an " +
            "entry (S',s) <--> (T,t), then the outgoing source transport address is (T,t)\" - and none does");

        var bytes = packet.ToArray();
        RewritePorts(bytes.AsSpan(head.Transport + 8 + quoted.Transport), quoted.Protocol, null, binding.MappedPort);
        return ToV4(bytes, quoted.Protocol, binding, ste: null, path, hairpin: false);
    }

    // --- §3.4's fragment conditions --------------------------------------------------------------------------------------
    // A fragment other than the first has no ports to key a session on, so the binding the first one settled is
    // kept under the identity every fragment of the datagram carries. §3.4 leaves the how of this open and names
    // the option: the NAT64 "MAY translate the fragments as they arrive, by storing information that allows it to
    // compute the 5-tuple for fragments other than the first".
    private Nat64Outcome ReplayFragment64(ReadOnlySpan<byte> packet, Siit.V6Header head, byte protocol,
        Siit.PathMtu path)
    {
        var key = new FragKey(protocol, Address(packet, 8, AddressFamily.InterNetworkV6),
            Address(packet, 24, AddressFamily.InterNetworkV6), head.Identification);
        if (!_fragments.TryGetValue(key, out var record)) return NoFragmentRecord();
        record.Expires = _now() + FragmentWindow;
        Interlocked.Increment(ref FragmentReuses);
        return ToV4(packet.ToArray(), protocol, record.Binding, ste: null, path, hairpin: false);
    }

    private Nat64Outcome ReplayFragment46(ReadOnlySpan<byte> packet, Siit.V4Header head, byte protocol,
        Siit.PathMtu path)
    {
        var key = new FragKey(protocol, Address(packet, 12, AddressFamily.InterNetwork),
            Address(packet, 16, AddressFamily.InterNetwork), head.Identification);
        if (!_fragments.TryGetValue(key, out var record)) return NoFragmentRecord();
        record.Expires = _now() + FragmentWindow;
        Interlocked.Increment(ref FragmentReuses);
        return ToV6(packet.ToArray(), record.Binding, path, hairpin: false);
    }

    private Nat64Outcome NoFragmentRecord()
    {
        Interlocked.Increment(ref FragmentRefused);
        return new Nat64Outcome(Nat64Action.Discard, null,
            "§3.4: no first fragment of this datagram came through, so nothing here allows its later ones to be " +
            "turned into a 5-tuple");
    }

    private void RecordFragment(byte protocol, IPAddress source, IPAddress destination, uint identification,
        Bib binding)
    {
        var key = new FragKey(protocol, source, destination, identification);
        if (_fragments.ContainsKey(key)) return;
        // The ceiling is §3.4's first bullet: "The NAT64 MUST limit the amount of resources devoted to the
        // storage of fragmented packets in order to protect from DoS attacks." A record past it is refused rather
        // than evicting one still inside the window §3.4's second bullet asks for.
        if (_fragments.Count >= FragmentCeiling)
        {
            Interlocked.Increment(ref FragmentRefused);
            return;
        }
        var record = new FragMap(binding);
        record.Expires = _now() + FragmentWindow;
        _fragments[key] = record;
    }

    // --- §3.5.1.1's and §3.5.2.3's allocation ----------------------------------------------------------------------------

    // The IPv4 address is §3.5.1.1's first bullet read against a pool of one: the address of the interface this
    // table answers on. The port is its second, third and fourth bullets in that order: the client's own port
    // when it is free, then a port in the same range with the same parity, then the range's other parity, then
    // the next range. The cursor is left on the port it returned, which is what spreads a hundred clients of one
    // address across the range instead of piling them onto one neighbour.
    private Bib BindingFor(BibKey key)
    {
        lock (_alloc)
        {
            if (_bibs.TryGetValue(key, out var existing)) return existing;
            var port = AllocatePortLocked(key.Proto, key.Port);
            // A binding that could not be given a port is not put in the table: §3.5.1.1's last paragraph makes
            // that packet a discard, and a half-made binding would answer the next one from an address pair that
            // nothing on the IPv4 side would recognise.
            if (port is null) return new Bib(key, null);
            var binding = new Bib(key, port);
            _bibs[key] = binding;
            _reverse[new ReverseKey(key.Proto, port.Value)] = key;
            Interlocked.Increment(ref Bindings);
            return binding;
        }
    }

    private ushort? AllocatePortLocked(byte proto, ushort clientPort)
    {
        // The ICMP query binding's identifier space is the whole 16-bit field, because §3.5.3 asks only for a
        // value "for which no other entry exists with the same (IPv4 address, ICMPv4 Identifier) pair"; TCP and
        // UDP keep to the range the reply leg can see.
        var floor = proto == IcmpProto ? (ushort)0 : PortFirst;
        var span = 0x10000 - floor;
        if (clientPort >= floor && Available(proto, clientPort)) return clientPort;
        var start = _cursor >= floor ? _cursor - floor : 0;
        for (var attempt = 0; attempt < 2; attempt++)
        for (var step = 0; step < span; step++)
        {
            var candidate = (ushort)(floor + (start + step) % span);
            if (attempt == 0 && (candidate & 1) != (clientPort & 1)) continue;
            if (Available(proto, candidate))
            {
                _cursor = candidate;
                return candidate;
            }
        }
        return null;
    }

    private bool Available(byte proto, ushort port) =>
        port != 0 && !_reverse.ContainsKey(new ReverseKey(proto, port)) &&
        (_localPorts is null || !_localPorts(proto).Contains(port)) &&
        (_otherMapped is null || !_otherMapped(proto).Contains(port));

    private Nat64Outcome NoAllocation()
    {
        Interlocked.Increment(ref Exhausted);
        return new Nat64Outcome(Nat64Action.Discard, null,
            "§3.5.1.1: \"If it is not possible to allocate an appropriate IPv4 transport address or create a BIB " +
            "entry, then the packet is discarded\" - with an ICMPv6 Destination Unreachable Code 3 only as a SHOULD, " +
            "which is the branch this translator does not take");
    }

    // --- the tables -----------------------------------------------------------------------------------------------------

    private Ste Session(SteKey key, Bib binding, IPAddress peerV4, DateTime expires, TcpState? state = null)
    {
        lock (_alloc)
        {
            if (_sessions.TryGetValue(key, out var live))
            {
                live.Expires = expires;
                if (state is { } first && live.State == TcpState.None) live.State = first;
                return live;
            }
            var ste = new Ste(key, binding, peerV4, expires, state ?? TcpState.None);
            _sessions[key] = ste;
            binding.Attach(ste);
            Interlocked.Increment(ref Sessions);
            return ste;
        }
    }

    /// §3.5.1's, §3.5.2.2's and §3.5.3's Address-Dependent Filtering, read as §3.5.1 puts it: the session must
    /// already name this IPv4 source address as one the client sent to. The scan is over the sessions of one
    /// binding, which §3.1 keeps short by deleting a binding when its last session goes.
    private static Ste? Allowed(Bib binding, IPAddress remote) => binding.MatchSession(remote);

    private Nat64Outcome FilteringFailure()
    {
        Interlocked.Increment(ref Filtered);
        return new Nat64Outcome(Nat64Action.Discard, null,
            "§3.5.1: with Address-Dependent Filtering on its IPv4 interface the NAT64 searches for a session whose " +
            "source IPv4 transport address is the packet's destination and whose destination IPv4 address is the " +
            "packet's source, and \"if such an entry is found ... packet processing continues. Otherwise, the packet " +
            "is discarded\" - the Type 3 Code 13 the paragraph permits is the branch this translator does not take");
    }

    public void Sweep()
    {
        var now = _now();
        lock (_alloc)
        {
            foreach (var (key, ste) in _sessions)
            {
                if (now < ste.Expires) continue;
                // §3.5.2.2 gives every state its own expiry consequence, and all of them end with the session
                // deleted. ESTABLISHED is the one that adds "the NAT64 SHOULD send a probe packet ... The state is
                // moved to TRANS": the probe is a packet this table does not originate, so the state moves and the
                // short timer is armed, which leaves the session standing for another TCP_TRANS and deletes it on a
                // later sweep - four minutes after the silence rather than at the end of its own two hours.
                if (ste.State == TcpState.Established)
                {
                    ste.State = TcpState.Trans;
                    ste.Expires = now + TcpTransitory;
                    continue;
                }
                ste.State = TcpState.Closed;
                if (!_sessions.TryRemove(key, out _)) continue;
                // §3.1: "Dynamically created entries are deleted from the corresponding BIB when the last session
                // associated with the BIB entry is removed from the session table."
                if (ste.Binding.Detach(ste))
                {
                    if (ste.Binding.MappedPort is { } port) _reverse.TryRemove(new ReverseKey(ste.Binding.Key.Proto, port), out _);
                    _bibs.TryRemove(ste.Binding.Key, out _);
                }
            }
        }
        foreach (var (key, record) in _fragments)
            if (now >= record.Expires) _fragments.TryRemove(key, out _);
    }

    // --- §3.6 and §3.7: the outgoing tuple, then the packet ---------------------------------------------------------------

    // §3.6's NOTE is the rule the map follows: a binding translates an IPv6 source transport address to an IPv4
    // one and an IPv4 destination transport address to an IPv6 one, and "the latter cases are handled by applying
    // the algorithmic transformation described in Section 3.5.4". Reading the NOTE against the roles the
    // translator sees rather than against the packet's direction is what makes it cover an ICMP error's embedded
    // header too: §4.3 and §5.3 give the quoted header "the function that translated the outer IP headers", and in
    // a quote the roles are crossed, so the address that names us appears as a source.
    private Siit.AddressMap MapFor(Bib binding, bool hairpinSource)
    {
        var client = binding.Key.V6;
        var ours = _wanAddress;
        return (IPAddress source, IPAddress destination, out IPAddress? mappedSource, out IPAddress? mappedDestination) =>
        {
            mappedSource = One(client, ours, source, hairpinSource);
            // The flag belongs to the source slot alone. §3.6.1's IPv4-to-IPv6 rule generates the source from the
            // address and takes the destination from the binding, and on a hairpin's second pass both slots are this
            // translator's own address - so the rule that makes the first one an embedding in the prefix has to leave
            // the second one the client the binding names, which is the only way B ever sees the datagram again.
            mappedDestination = One(client, ours, destination, hairpinSource: false);
            return mappedSource is not null && mappedDestination is not null;
        };
    }

    private IPAddress Embed(IPAddress v4) => Pref64.Embed(_prefix.Prefix, _prefix.PrefixLength, v4);

    private IPAddress? One(IPAddress client, IPAddress ours, IPAddress address, bool hairpinSource)
    {
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            if (!address.Equals(ours)) return Embed(address);
            // A hairpin's source is this address in the other family, not the client that owns the binding:
            // §3.6.1's IPv4-to-IPv6 rule generates the source from the address, and §3.6's NOTE is explicit that a
            // binding is not used for that direction.
            return hairpinSource ? Embed(ours) : client;
        }
        return address.Equals(client) ? ours : Pref64.Extract(_prefix.Prefix, _prefix.PrefixLength, address);
    }

    // §3.7's first modification is the NAT64's own: "the source and destination ports are modified to the source
    // and destination ports from the outgoing 5-tuple ... note that the TCP and UDP checksum covers the
    // pseudo-header". Writing them into the packet before the translation runs is what lets RFC 7915's own
    // checksum work cover them, and §3.7 points at RFC 3022 for exactly that update.
    private byte[] Rewritten64(ReadOnlySpan<byte> packet, Siit.V6Header head, Bib binding)
    {
        var bytes = packet.ToArray();
        RewritePorts(bytes.AsSpan(head.Transport), head.Protocol, binding.MappedPort, null);
        return bytes;
    }

    private Nat64Outcome ToV4(byte[] packet, byte protocol, Bib binding, Ste? ste, Siit.PathMtu path, bool hairpin)
    {
        if (!Siit.TryV6ToV4(packet, MapFor(binding, hairpinSource: false), _identification.Next(), path,
                out var translated, out var why))
            return new Nat64Outcome(Nat64Action.Discard, null, why);
        Interlocked.Increment(ref Translated64);
        return Hairpin(translated!, protocol, path, hairpin, ste);
    }

    private Nat64Outcome ToV6(byte[] packet, Bib binding, Siit.PathMtu path, bool hairpin)
    {
        if (!Siit.TryV4ToV6(packet, MapFor(binding, hairpin), path, out var translated, out var why))
            return new Nat64Outcome(Nat64Action.Discard, null, why);
        Interlocked.Increment(ref Translated46);
        return new Nat64Outcome(Nat64Action.Translate, translated);
    }

    // §3.8: "The outgoing 5-tuple becomes the incoming 5-tuple. The packet is treated as if it was received on
    // the outgoing interface. Processing of the packet continues at step 2." That is this call. The flag that
    // comes with it is what §3.6.1 needs to keep the source algorithmic and what keeps a hairpin from turning
    // into the loop §3.5's first rule exists to prevent. §2's own definition limits hairpin packets to TCP and
    // UDP, so an ICMP query's translation is never re-entered.
    private Nat64Outcome Hairpin(byte[] translated, byte protocol, Siit.PathMtu path, bool alreadyHairpin,
        Ste? ste)
    {
        if (alreadyHairpin || ste is null || protocol == Icmpv6Proto ||
            !Address(translated, 16, AddressFamily.InterNetwork).Equals(_wanAddress))
            return new Nat64Outcome(Nat64Action.Translate, translated);
        Interlocked.Increment(ref Hairpins);
        return FromIpv4(translated, path, hairpin: true);
    }

    // --- helpers ----------------------------------------------------------------------------------------------------------

    /// RFC 7915 §5.1's "Fragment Identification generator at the translator", which RFC 6146 §3.7 leaves to the
    /// algorithm it names. One counter for the whole table, and an IPv6 datagram's own Identification is §5.1.1's
    /// case, copied instead of generated.
    private sealed class FragmentIdentification
    {
        private uint _value;
        public ushort Next() => (ushort)Interlocked.Increment(ref _value);
    }

    // The two ports are the first four octets of every transport header this table rewrites, so a short span -
    // which is what a truncated quote inside an error message is - still gets both of them; only the checksum
    // needs the field at its own offset, and the fold is skipped when either the field or the sum is not there.
    // A UDP checksum of zero says the sender computed none, and there is no sum to move: RFC 7915 recomputes
    // whatever it translates for a whole datagram, and §3.4's zero-checksum bullet is satisfied by that.
    private static void RewritePorts(Span<byte> transport, byte protocol, ushort? source, ushort? destination)
    {
        if (transport.Length < 4) return;
        var field = protocol == TcpProto ? 16 : 6;
        var stored = transport.Length >= field + 2
            ? BinaryPrimitives.ReadUInt16BigEndian(transport.Slice(field, 2))
            : (ushort)0;
        var fold = stored != 0;
        if (source is { } s)
        {
            if (fold) stored = Update(stored, BinaryPrimitives.ReadUInt16BigEndian(transport[..2]), s);
            BinaryPrimitives.WriteUInt16BigEndian(transport[..2], s);
        }
        if (destination is { } d)
        {
            if (fold) stored = Update(stored, BinaryPrimitives.ReadUInt16BigEndian(transport.Slice(2, 2)), d);
            BinaryPrimitives.WriteUInt16BigEndian(transport.Slice(2, 2), d);
        }
        if (!fold) return;
        // RFC 1071 §1.4: "to represent minus zero, use a value of 16'hFFFF instead of 16'h0000", which for UDP is
        // also the difference between a checksum that says zero and one that says none.
        if (stored == 0) stored = 0xFFFF;
        BinaryPrimitives.WriteUInt16BigEndian(transport.Slice(field, 2), stored);
    }

    // RFC 1624 §2's update, which §3.7 reaches through RFC 3022: HC' = ~(C + (-m) + m'), with every addition in
    // one's complement and C the one's complement of the stored checksum.
    private static ushort Update(ushort checksum, ushort oldWord, ushort newWord)
    {
        var sum = (uint)(ushort)~checksum + (uint)(ushort)~oldWord + newWord;
        sum = (sum & 0xFFFF) + (sum >> 16);
        sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~(ushort)sum;
    }

    private static (ushort Source, ushort Destination) ReadPorts(ReadOnlySpan<byte> transport)
        => (BinaryPrimitives.ReadUInt16BigEndian(transport[..2]),
            BinaryPrimitives.ReadUInt16BigEndian(transport.Slice(2, 2)));

    private static IPAddress Address(ReadOnlySpan<byte> packet, int offset, AddressFamily family)
        => new(packet.Slice(offset, family == AddressFamily.InterNetworkV6 ? 16 : 4).ToArray());

    private static bool IsIcmp4Error(ReadOnlySpan<byte> message) => message[0] is 3 or 11 or 12;

    // RFC 4443 §2.4's note is the definition this uses: "for the purposes of this document, ICMPv6 error messages
    // are those with a Type value of 1 through 127". Types 3 and 4 - Time Exceeded and Parameter Problem - are in
    // that range and are rows of §5.2's table, so reading the set as only the first two would send them down the
    // Query path with a 3-tuple taken from a field that holds an MTU or a Pointer.
    private static bool IsIcmp6Error(ReadOnlySpan<byte> message) => message[0] < 128;

    // The packet quoted inside an ICMP error, read as RFC 7915 §4.3's figure puts it: behind the eight octets of
    // the error's own header, and with the quoted header's own length rather than a fixed twenty.
    private bool TryEmbedded(ReadOnlySpan<byte> packet, Siit.V4Header head, out ReadOnlySpan<byte> inner,
        out Siit.V4Header quoted, out string why)
    {
        inner = default;
        quoted = default;
        why = "";
        var at = head.Transport + 8;
        if (packet.Length < at + 20)
        {
            why = "the message stops before an internet header could be quoted inside it";
            return false;
        }
        if (!Siit.TryReadV4(packet[at..], true, out var innerHead, out _))
        {
            why = "the quoted packet is not an IPv4 header this translation can read";
            return false;
        }
        // innerHead's offsets are measured from the start of the quote, and a quote inside an error message is
        // allowed to be a partial header, so the octets that are actually here bound the slice, not Total Length.
        var slice = packet.Slice(at, Math.Min(innerHead.DatagramEnd, packet.Length - at));
        // RFC 5508's REQ-3a is the clause that says what a quote that does not add up is worth: "if the IP
        // checksum of the embedded packet fails to validate, the NAT SHOULD silently drop".
        if (Checksum(slice[..innerHead.Transport]) != 0)
        {
            why = "the quoted IP header does not validate";
            return false;
        }
        inner = slice;
        quoted = innerHead;
        return true;
    }

    // The packet quoted inside an ICMPv6 error, read the way RFC 7915 §5.3's figure puts it: eight octets behind
    // the message's own header and bounded by the quoted header's own length, of which only part may be here.
    // RFC 8200 §3's base header carries no checksum field, so this is where the IPv4 helper's RFC 5508 REQ-3a test
    // has no counterpart - the message's own checksum is the only one an IPv6 error brings, and §5.3 asks for the
    // quote to be translated whether or not the sender kept it consistent.
    private static bool TryEmbedded64(ReadOnlySpan<byte> packet, Siit.V6Header head, out ReadOnlySpan<byte> inner,
        out Siit.V6Header quoted, out string why)
    {
        inner = default;
        quoted = default;
        why = "";
        var at = head.Transport + 8;
        if (packet.Length < at + Ipv6Chain.HeaderLength)
        {
            why = "the message stops before an internet header could be quoted inside it";
            return false;
        }
        if (!Siit.TryReadV6(packet[at..], true, out var innerHead, out _))
        {
            why = "the quoted packet is not an IPv6 packet this translation can read";
            return false;
        }
        inner = packet.Slice(at, Math.Min(innerHead.DatagramEnd, packet.Length - at));
        quoted = innerHead;
        return true;
    }

    // RFC 791 §3.1's check, run with the checksum field in place: a header that adds up leaves zero behind.
    private static ushort Checksum(ReadOnlySpan<byte> data)
    {
        uint sum = 0;
        for (var i = 0; i + 1 < data.Length; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(data.Slice(i, 2));
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~sum;
    }

    public readonly record struct BibKey(byte Proto, IPAddress V6, ushort Port);

    private sealed class Bib(BibKey key, ushort? mappedPort)
    {
        public BibKey Key { get; } = key;
        public ushort? MappedPort { get; } = mappedPort;
        private readonly List<Ste> _sessions = [];

        public void Attach(Ste ste)
        {
            lock (_sessions) _sessions.Add(ste);
        }

        /// The first of this binding's sessions that names that IPv4 address, which is what the filtering
        /// paragraphs of §3.5.1, §3.5.2.2 and §3.5.3 ask for by address rather than by transport address.
        public Ste? MatchSession(IPAddress remote)
        {
            lock (_sessions)
            {
                foreach (var ste in _sessions)
                    if (ste.PeerV4.Equals(remote)) return ste;
                return null;
            }
        }

        /// True when this was the binding's last session, which is §3.1's condition for deleting the binding.
        public bool Detach(Ste ste)
        {
            lock (_sessions)
            {
                _sessions.Remove(ste);
                return _sessions.Count == 0;
            }
        }
    }

    private readonly record struct ReverseKey(byte Proto, ushort Mapped);

    public readonly record struct SteKey(byte Proto, IPAddress V6Source, ushort SourcePort,
        IPAddress V6Dest, ushort DestPort);

    private sealed class Ste(SteKey key, Bib binding, IPAddress peerV4, DateTime expires, TcpState state)
    {
        public SteKey Key { get; } = key;
        public Bib Binding { get; } = binding;
        public IPAddress PeerV4 { get; } = peerV4;
        public DateTime Expires = expires;
        public TcpState State = state;
    }

    private readonly record struct FragKey(byte Proto, IPAddress Source, IPAddress Destination, uint Id);

    private sealed class FragMap(Bib binding)
    {
        public Bib Binding { get; } = binding;
        public DateTime Expires;
    }

    public enum TcpState
    {
        /// §3.5.2.1's CLOSED, "a fictional state when there is no state for that particular connection in the
        /// NAT64", and the one a UDP or ICMP query session of this table never leaves.
        None,
        V6Init,
        Established,
        V6FinRcv,
        V4FinRcv,
        BothFinRcv,
        Trans,
        Closed,
    }
}
