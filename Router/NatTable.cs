using System.Buffers.Binary;
using System.Collections.Concurrent;

namespace Router;

public enum NatAction { None, Snat, Dnat, IcmpError, Discard }

// What to do with the packet, and nothing about where it goes: at the forward layer the routing decision
// has already been made, the egress is fixed by it rather than by anything a rewrite could write into the
// address, so the only thing a rewrite changes here is the addresses inside the packet. Program.cs
// reinjects with the address it was given.
//
// Discard is the one action that is not a rewrite: the caller owns the packet buffer and has to know not
// to put the packet back, which is what RFC 5508 REQ-4 asks for when an error quotes no flow of ours.
// Reason rides along because a dropped packet otherwise leaves nothing but a counter, and a counter cannot
// be told apart from the path's own failure.
public readonly record struct NatOutcome(NatAction Action, string? Reason = null);

// Stateless about sockets and about WinDivert: it is handed one packet at a time and rewrites the
// address and transport identifiers in place. Everything here is exercised offline by
// tests/natcheck, which needs no driver and no admin.
public sealed class NatTable
{
    private const byte IcmpProto = 1;
    private const byte TcpProto = 6;
    private const byte UdpProto = 17;

    private const byte IcmpEchoReply = 0;
    private const byte IcmpEchoRequest = 8;
    private const byte IcmpTimestampRequest = 13;
    private const byte IcmpTimestampReply = 14;

    // RFC 5508 REQ-10a puts Destination Unreachable and Time Exceeded in the MUST-support set, and they
    // are the two that carry a path MTU a LAN client needs. Redirect and Parameter Problem are the MAYs,
    // Source Quench a SHOULD NOT, so those stay on the path a packet takes when nothing here claims it.
    private const byte IcmpDestUnreachable = 3;
    private const byte IcmpTimeExceeded = 11;

    // An error's ICMP header is four octets of type/code/checksum plus four that RFC 791 §3.1 puts the
    // quoted packet after, and the quote itself is that packet's internet header and its first 64 bits.
    // RFC 4884 §4.1 re-purposes those four octets as a length counted in 32-bit words over the quoted
    // packet, so a non-zero value says extensions follow the quote, never that the quote moved.
    private const int IcmpHeaderOctets = 8;
    private const int QuotedTransportOctets = 8;

    // RFC 5382 REQ-5 puts the floor for an established TCP mapping at 2 hours 4 minutes and for a
    // transitory one at 4 minutes; RFC 4787 REQ-5 puts the UDP floor at two minutes; RFC 5508 REQ-2
    // puts the ICMP query session floor at 60 seconds. These are the floors, not tuning.
    private static readonly TimeSpan TcpEstablishedIdle = TimeSpan.FromMinutes(124);
    private static readonly TimeSpan TcpTransitoryIdle = TimeSpan.FromMinutes(4);
    private static readonly TimeSpan IcmpIdle = TimeSpan.FromSeconds(60);

    // How long a first fragment's rewrite stays on hand for the fragments behind it. This is our own
    // bound, not a floor from the standards: RFC 4787 §11 REQ-14a asks only that "a NAT's out-of-order
    // fragment processing mechanism MUST be designed so that fragmentation-based DoS attacks do not
    // compromise the NAT's ability to process in-order and unfragmented IP packets", and a record that
    // lives past any plausible reassembly window is a record nobody will ever ask for again.
    private static readonly TimeSpan FragmentWindow = TimeSpan.FromSeconds(60);
    private const int FragmentCeiling = 4096;

    // RFC 791 §3.1 puts the flags and the fragment offset in one 16-bit field at header offset 6: the
    // offset is the low 13 bits and More Fragments is 0x2000. A first fragment with nothing behind it
    // is an ordinary datagram, and only the one with MF set has a follow-on packet that will ask for
    // its rewrite.
    private const ushort MoreFragments = 0x2000;

    // "A NAT UDP mapping timer MUST NOT expire in less than two minutes" - but the same REQ-5 continues
    // "A default value of five minutes or more for the NAT UDP mapping timer is RECOMMENDED", which is
    // why the default is not the floor. The floor stays a hard refusal: --udp-timeout below it is a
    // configuration that cannot be honoured, not a preference to round.
    public static readonly TimeSpan UdpTimeoutFloor = TimeSpan.FromMinutes(2);
    public const int UdpTimeoutDefaultSeconds = 300;

    // The dynamic range, RFC 6335 §6: a mapped port must not collide with a service port on the WAN
    // address, and nothing in 49152-65535 is assigned one. Allocation works in slots of two consecutive
    // ports (RFC 4787 REQ-4: "It is RECOMMENDED that a NAT have a 'Port parity preservation' behavior
    // of 'Yes'"), so a slot is one even port and the odd port above it.
    // PortFirst is also what the reply leg's filter asks for: a destination port at or above it is the only
    // thing that tells an answer to one of our flows apart from the host's own inbound traffic.
    public const ushort PortFirst = 49152;
    private const ushort PortLast = 65535;
    private const int PortSlots = (PortLast - PortFirst + 1) / 2;

    // The source a SNAT writes and the destination a reply is recognised by. Not a constant: a WAN that
    // renews its lease changes it while the run goes on - a phone hotspot reassociating is the ordinary
    // case for this program - and a source the interface no longer owns is a packet the upstream throws
    // away as spoofed. Written only by the sweep loop, read once per packet.
    private volatile uint _wanAddr;
    private readonly uint _lanAddr;
    private readonly uint _lanNetwork;
    private readonly uint _lanMask;
    private readonly Func<DateTime> _now;
    private readonly TimeSpan _udpIdle;
    private readonly ConcurrentDictionary<MapKey, Flow> _flows = new();
    private readonly ConcurrentDictionary<RevKey, MapKey> _rev = new();
    // The rewrite a datagram's first fragment got, kept under the identity the rest of its fragments
    // carry: RFC 791 §3.2 makes (protocol, source, destination, id) the reassembly key, and a NAT that
    // rewrites only the fragment holding the transport header leaves the others addressed to the client.
    private readonly ConcurrentDictionary<FragKey, FragVal> _frag = new();
    private readonly object _alloc = new();
    private int _cursor;

    public long Snats;
    public long Dnats;
    public long LocalDest;
    public long Fragments;
    public long FragmentRewrites;
    public long UnmappedProtocol;
    public long WrongIf;
    public long IcmpErrors;
    public long IcmpErrorsDropped;

    // Addresses are held as the four octets read big-endian, so 192.168.2.1 is 0xC0A80201. That is
    // the readable form and the form a filter string wants; it is NOT the form NativeIpv4Header
    // fields hold on this architecture, which is why Program.cs byte-swaps at the boundary.
    public NatTable(uint wanAddr, uint lanAddr, uint lanMask, Func<DateTime>? now = null, TimeSpan? udpIdle = null)
    {
        _wanAddr = wanAddr;
        _lanAddr = lanAddr;
        _lanMask = lanMask;
        _lanNetwork = lanAddr & lanMask;
        _now = now ?? (() => DateTime.UtcNow);
        var requested = udpIdle ?? TimeSpan.FromSeconds(UdpTimeoutDefaultSeconds);
        if (requested < UdpTimeoutFloor)
            throw new ArgumentOutOfRangeException(nameof(udpIdle),
                $"the UDP mapping timer has a floor of {UdpTimeoutFloor.TotalSeconds:0} seconds");
        _udpIdle = requested;
    }

    public int FlowCount => _flows.Count;

    public uint WanAddress => _wanAddr;

    // The whole table moves to the new address in one step, because nothing in it keys on the address: the
    // reverse lookup is the mapped port alone, which is RFC 4787 REQ-1's endpoint-independent mapping. What
    // a change costs is the flows a peer already saw under the old source - and those are broken at the
    // peer rather than here, so they are left to time out instead of flushed.
    public void SetWanAddress(uint wanAddr) => _wanAddr = wanAddr;

    // Whether a transport port is one this table handed out. The trace asks this to keep following a
    // packet after the rewrite: once SNAT has run, neither address is a LAN address, so an
    // address-based filter loses it exactly where the interesting part begins - the copy the host
    // forwards out the WAN interface, and the reply that comes back to the mapped port.
    public bool IsMappedPort(byte proto, ushort port) => _rev.ContainsKey(new RevKey(proto, port));

    public bool IsLanAddress(uint addr) => (addr & _lanMask) == _lanNetwork;

    public NatOutcome Translate(Span<byte> packet, int egressIfIdx, int wanIfIdx)
    {
        if (packet.Length < 20 || (packet[0] >> 4) != 4)
            return new NatOutcome(NatAction.None);

        var ihl = (packet[0] & 0x0F) * 4;
        if (ihl < 20 || packet.Length < ihl)
            return new NatOutcome(NatAction.None);

        var proto = packet[9];
        var src = ReadAddr(packet, 12);
        var dst = ReadAddr(packet, 16);
        var id = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(4, 2));

        // The offset is the whole question here: a non-zero one says this packet is not the fragment
        // carrying the transport header, so the address rewrite it needs is the one already recorded for
        // its datagram (RFC 791 §3.2 makes the id and the offset the reassembly key, and this table
        // touches neither). A first fragment with more behind it still has offset zero and comes through
        // here as the datagram's header carrier.
        var flags = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(6, 2));
        if ((flags & 0x1FFF) != 0)
            return TranslateFragment(packet, proto, src, dst, id);
        var moreFragments = (flags & MoreFragments) != 0;

        // A reply to the WAN address that carries a mapped port is that flow's reply, and the mapping is
        // endpoint-independent (RFC 4787 REQ-1), so it is matched on the port alone and before any
        // interface condition: the answer can legitimately come back through a different route than the
        // query left by.
        if (dst == _wanAddr)
        {
            if (proto is not (TcpProto or UdpProto or IcmpProto))
            {
                Interlocked.Increment(ref UnmappedProtocol);
                return new NatOutcome(NatAction.None);
            }
            if (IsIcmpError(packet, ihl))
                return TranslateError(packet, ihl);
            if (!TryReadPorts(packet, ihl, proto, out _, out var replyPort))
                return new NatOutcome(NatAction.None);
            if (!IsMappedQuery(proto, packet, ihl, reply: true))
                return new NatOutcome(NatAction.None);

            var revKey = new RevKey(proto, replyPort);
            if (_rev.TryGetValue(revKey, out var mapKey) && _flows.TryGetValue(mapKey, out var flow))
            {
                if (moreFragments)
                    RecordFragment(proto, src, _wanAddr, id, new FragVal(NatAction.Dnat, 16, flow.Key.ClientIp));
                WriteAddr(packet, 16, flow.Key.ClientIp);
                WritePort(packet, ihl, proto, flow.Key.ClientPort, destination: true);
                if (moreFragments)
                    FoldTransportChecksum(packet, ihl, proto, _wanAddr, flow.Key.ClientIp,
                        replyPort, flow.Key.ClientPort);
                Touch(flow, proto, packet, ihl, src);
                Interlocked.Increment(ref Dnats);
                return new NatOutcome(NatAction.Dnat);
            }

            // Addressed to us and not mapped: leave it for the local stack, which is how the DHCP and
            // DNS listeners on this interface stay reachable.
            Interlocked.Increment(ref LocalDest);
            return new NatOutcome(NatAction.None);
        }

        if (egressIfIdx != wanIfIdx)
        {
            // Counted for the one shape on this branch that means something is misconfigured: a packet
            // from a LAN source to an off-link destination that the routing table is sending back out the
            // LAN interface. Either --wan resolved to the wrong interface, or this host reaches that
            // destination through a neighbour on the LAN rather than through itself - and in both cases
            // the client's traffic is being forwarded by someone else, so rewriting it here would be
            // wrong. Every other path in this method works with a wrong index, so nothing else says it.
            if (IsLanAddress(src) && !IsLanAddress(dst))
                Interlocked.Increment(ref WrongIf);
            return new NatOutcome(NatAction.None);
        }

        // Multicast and the limited broadcast are not forwarding destinations: a DHCPDISCOVER to
        // 255.255.255.255 has to reach this host's own listener rather than be rewritten out the WAN.
        if (dst >> 28 >= 0xE)
            return new NatOutcome(NatAction.None);

        // Traffic between two LAN hosts and traffic to this interface's own address are both local
        // business; only a client reaching past the LAN is a forwarding candidate.
        if (!IsLanAddress(src) || IsLanAddress(dst) || src == _lanAddr)
            return new NatOutcome(NatAction.None);

        if (proto is not (TcpProto or UdpProto or IcmpProto))
        {
            Interlocked.Increment(ref UnmappedProtocol);
            return new NatOutcome(NatAction.None);
        }
        if (IsIcmpError(packet, ihl))
            return TranslateError(packet, ihl);
        if (!TryReadPorts(packet, ihl, proto, out var srcPort, out var dstPort))
            return new NatOutcome(NatAction.None);
        if (!IsMappedQuery(proto, packet, ihl, reply: false))
            return new NatOutcome(NatAction.None);

        var key = new MapKey(proto, src, srcPort);
        if (!_flows.TryGetValue(key, out var existing))
            existing = Create(key, dst);

        if (moreFragments)
            RecordFragment(proto, src, dst, id, new FragVal(NatAction.Snat, 12, _wanAddr));
        WriteAddr(packet, 12, _wanAddr);
        WritePort(packet, ihl, proto, existing.NatPort, destination: false);
        if (moreFragments)
            FoldTransportChecksum(packet, ihl, proto, src, _wanAddr, srcPort, existing.NatPort);
        Touch(existing, proto, packet, ihl, dst);
        Interlocked.Increment(ref Snats);
        return new NatOutcome(NatAction.Snat);
    }

    private Flow Create(MapKey key, uint remote)
    {
        lock (_alloc)
        {
            if (_flows.TryGetValue(key, out var raced))
                return raced;

            var port = AllocatePortLocked(key.Proto, key.ClientPort);
            var flow = new Flow(key, port, remote, _now());
            _flows[key] = flow;
            _rev[new RevKey(key.Proto, port)] = key;
            return flow;
        }
    }

    // "It is RECOMMENDED that a NAT have a 'Port parity preservation' behavior of 'Yes'" - RFC 4787
    // REQ-4. The cursor is deliberately left on the slot it just used instead of moving past it: the two
    // ports in a slot are consecutive, so the opposite-parity mapping that follows lands on the neighbour
    // rather than a whole slot further along, and a client that allocated an even/odd pair back to back
    // gets an even/odd pair out. Moving the cursor forward instead would keep the parity and lose the
    // adjacency.
    private ushort AllocatePortLocked(byte proto, ushort internalPort)
    {
        var parity = internalPort & 1;
        for (var step = 0; step < PortSlots; step++)
        {
            var slot = (_cursor + step) % PortSlots;
            var candidate = (ushort)(PortFirst + slot * 2 + parity);
            if (_rev.ContainsKey(new RevKey(proto, candidate))) continue;
            _cursor = slot;
            return candidate;
        }
        throw new InvalidOperationException("NAT port pool exhausted");
    }

    private static bool IsIcmpError(ReadOnlySpan<byte> packet, int ihl)
        => packet.Length >= ihl + IcmpHeaderOctets && packet[ihl] is IcmpDestUnreachable or IcmpTimeExceeded;

    // An error message quotes the packet that triggered it, and for a flow this table rewrote that quote
    // is in the rewritten form: the client cannot match it to a socket and neither can the peer outside,
    // so the path MTU it carries reaches nobody. RFC 5508 REQ-4 (an error from the external realm) and
    // REQ-5 (one from the private realm) both revert the quote with the mapping it belongs to, leave the
    // type and code alone, and point the outer header at the host the reverted quote now names.
    private NatOutcome TranslateError(Span<byte> packet, int ihl)
    {
        var inner = ihl + IcmpHeaderOctets;
        if (packet.Length < inner + 20 || (packet[inner] >> 4) != 4)
            return DropError("the quote is not an IPv4 header");
        // REQ-3b: the quoted transport header sits behind any IP options in the quoted packet, not at a
        // fixed offset 20.
        var innerIhl = (packet[inner] & 0x0F) * 4;
        if (innerIhl < 20 || packet.Length < inner + innerIhl + QuotedTransportOctets)
            return DropError("the quote stops before its transport ports");
        // REQ-3a: "if the IP checksum of the embedded packet fails to validate, the NAT SHOULD silently
        // drop" - a quote that does not add up is not one to forward on.
        if (OnesComplementSum(packet.Slice(inner, innerIhl)) != 0)
            return DropError("the quoted IP header does not validate");

        var transport = inner + innerIhl;
        var innerProto = packet[inner + 9];
        var innerSrc = ReadAddr(packet, inner + 12);
        var innerDst = ReadAddr(packet, inner + 16);
        if (!TryReadPorts(packet, transport, innerProto,
                out var innerSrcPort, out var innerDstPort))
            return DropError("the quoted transport header is not readable");
        // Read before anything is written: the peer end of the quote is the one address this table does
        // not own, and Touch wants it.
        var external = innerSrc == _wanAddr ? innerDst : innerSrc;

        Flow flow;
        uint quotedAddrOld, quotedAddrNew;
        ushort quotedPortOld, quotedPortNew;
        if (innerSrc == _wanAddr)
        {
            // The quote is one of our outgoing rewrites, so its source port is the mapped one and the
            // reverse lookup finds the flow - the same lookup a reply leg uses. REQ-4c then makes the
            // outer destination the embedded source after the revert, which is the client's own address.
            if (!_rev.TryGetValue(new RevKey(innerProto, innerSrcPort), out var mapKey) ||
                !_flows.TryGetValue(mapKey, out var found))
                return DropError($"no flow owns the quoted source port {innerSrcPort}");
            flow = found;
            WriteAddr(packet, inner + 12, flow.Key.ClientIp);
            WritePort(packet.Slice(transport), 0, innerProto, flow.Key.ClientPort, destination: false);
            WriteAddr(packet, 16, flow.Key.ClientIp);
            (quotedAddrOld, quotedAddrNew) = (_wanAddr, flow.Key.ClientIp);
            (quotedPortOld, quotedPortNew) = (innerSrcPort, flow.Key.ClientPort);
        }
        else if (IsLanAddress(innerDst) && !IsLanAddress(innerSrc))
        {
            // An error the client raised about a packet it received: the quote names the client at the
            // receiving end, so the flow is the client's own tuple and the quote goes the other way, out
            // to the public form. REQ-5c has the outer source become this table's public address, which
            // is also the only form that can leave this host at all.
            if (!_flows.TryGetValue(new MapKey(innerProto, innerDst, innerDstPort), out var found))
                return DropError($"no flow owns the quoted client tuple {FormatAddress(innerDst)}:{innerDstPort}");
            flow = found;
            WriteAddr(packet, inner + 16, _wanAddr);
            WritePort(packet.Slice(transport), 0, innerProto, flow.NatPort, destination: true);
            WriteAddr(packet, 12, _wanAddr);
            (quotedAddrOld, quotedAddrNew) = (flow.Key.ClientIp, _wanAddr);
            (quotedPortOld, quotedPortNew) = (innerDstPort, flow.NatPort);
        }
        else
        {
            return DropError("the quote names neither this host's WAN address nor a LAN client");
        }

        if (innerProto == UdpProto)
        {
            var hc = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(transport + 6, 2));
            // RFC 768: a UDP checksum field of zero says it was not computed, so there is nothing to keep.
            if (hc != 0)
            {
                hc = FoldChecksum(hc, quotedPortOld, quotedPortNew);
                hc = FoldChecksum(hc, (ushort)(quotedAddrOld >> 16), (ushort)(quotedAddrNew >> 16));
                hc = FoldChecksum(hc, (ushort)quotedAddrOld, (ushort)quotedAddrNew);
                // RFC 768 again: a computed UDP checksum of zero is sent as all ones, and a fold that
                // lands on zero would otherwise say "no checksum" where it means "here is one".
                BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(transport + 6, 2), hc == 0 ? (ushort)0xFFFF : hc);
            }
        }
        else if (innerProto == IcmpProto)
        {
            // The embedded query's own checksum has no pseudo-header over the addresses to redo (RFC 791
            // §3.1 leaves it over the message), so the identifier is its only changed term.
            var hc = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(transport + 2, 2));
            BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(transport + 2, 2), FoldChecksum(hc, quotedPortOld, quotedPortNew));
        }

        // The quoted internet header is present in full, so its checksum is recomputed rather than folded
        // - and it has to be, because an address inside it changed just above.
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(inner + 10, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(inner + 10, 2), OnesComplementSum(packet.Slice(inner, innerIhl)));

        // REQ-6: while processing an error about an ICMP query or its response, the NAT MUST NOT refresh or
        // delete the session the payload belongs to. An error about TCP or UDP is a step on that flow's
        // own path, and the timer is what keeps the mapping the client still needs alive.
        if (innerProto != IcmpProto)
            Touch(flow, innerProto, packet.Slice(transport), 0, external);

        Interlocked.Increment(ref IcmpErrors);
        return new NatOutcome(NatAction.IcmpError);
    }

    private NatOutcome DropError(string reason)
    {
        Interlocked.Increment(ref IcmpErrorsDropped);
        return new NatOutcome(NatAction.Discard, reason);
    }

    // RFC 4787 §11 REQ-14: "A NAT MUST support receiving in-order and out-of-order fragments". A
    // fragment behind the first has no transport header to read and no port to key on, so it is mapped
    // through the record the first one left behind. A fragment whose datagram never came through this
    // table - the first one was lost, or the host fragmented a packet this table does not forward - is
    // left exactly where it was: guessing an address for it would be inventing one.
    private NatOutcome TranslateFragment(Span<byte> packet, byte proto, uint src, uint dst, ushort id)
    {
        if (!_frag.TryGetValue(new FragKey(proto, src, dst, id), out var recorded))
        {
            Interlocked.Increment(ref Fragments);
            return new NatOutcome(NatAction.None);
        }

        WriteAddr(packet, recorded.Offset, recorded.NewAddr);
        Interlocked.Increment(ref FragmentRewrites);
        return new NatOutcome(recorded.Action);
    }

    // The rewrite is refreshed on every first fragment that comes through, so a datagram id reused by a
    // long-lived flow stays as long as the traffic does. Past the ceiling a new datagram is simply not
    // recorded - which is RFC 4787 §11 REQ-14a's point that fragment handling must not become a way to
    // exhaust the NAT, and an unrecorded datagram loses nothing beyond what the table already did.
    private void RecordFragment(byte proto, uint src, uint dst, ushort id, FragVal val)
    {
        var key = new FragKey(proto, src, dst, id);
        if (_frag.ContainsKey(key) || _frag.Count < FragmentCeiling)
            _frag[key] = val with { Expires = _now() };
    }

    // RFC 1624 §2: HC' = ~(C + (-m) + m') with C the sum the old HC is the complement of. It is the only
    // form available for a quoted transport header, since the quote stops at 64 bits of the datagram and
    // the rest of what the checksum covered is not on hand.
    private static ushort FoldChecksum(ushort hc, ushort oldWord, ushort newWord)
    {
        uint sum = (uint)(~hc & 0xFFFF) + (uint)(~oldWord & 0xFFFF) + newWord;
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)(~sum & 0xFFFF);
    }

    // A first fragment whose address or port this table changed carries the transport checksum of the
    // whole datagram, and the rest of that datagram is in fragments that never came through here, so the
    // checksum cannot be recomputed - only updated. RFC 1624 §2 is the form that needs just the changed
    // words, and the changed words are all this table has: the two halves of the address it rewrote and
    // the one port, since RFC 791 §3.1's pseudo-header length term is the reassembled datagram's and no
    // NAT rewrite touches it.
    // Program.cs's reinject calls the driver's CalcChecksums for every packet, and that is what gives an
    // unfragmented datagram its transport checksum. Measured on this driver: the same call on a first
    // fragment returns false and leaves the transport field exactly as it found it (it does still fix the
    // IPv4 header checksum), so the fold below is the only thing that keeps the far host's reassembled
    // datagram validating instead of being silently discarded there.
    private static void FoldTransportChecksum(Span<byte> packet, int ihl, byte proto,
        uint addrOld, uint addrNew, ushort portOld, ushort portNew)
    {
        var field = proto switch
        {
            TcpProto => ihl + 16,
            UdpProto => ihl + 6,
            IcmpProto => ihl + 2,
            _ => -1,
        };
        if (field < 0 || packet.Length < field + 2) return;
        var hc = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(field, 2));
        // RFC 768: zero in a UDP checksum field says it was not computed, so there is nothing to update
        // and a fold would invent a checksum the sender never meant to send.
        if (proto == UdpProto && hc == 0) return;
        hc = FoldChecksum(hc, portOld, portNew);
        // RFC 1071 §1.4: TCP and UDP run their checksum over a pseudo-header that carries the two
        // addresses. ICMP's runs over the message alone (RFC 791 §3.1), so for it the identifier above is
        // the only changed term and folding the addresses in would corrupt a valid checksum.
        if (proto != IcmpProto)
        {
            hc = FoldChecksum(hc, (ushort)(addrOld >> 16), (ushort)(addrNew >> 16));
            hc = FoldChecksum(hc, (ushort)addrOld, (ushort)addrNew);
        }
        // RFC 768 again: a computed UDP checksum of zero is sent as all ones.
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(field, 2),
            proto == UdpProto && hc == 0 ? (ushort)0xFFFF : hc);
    }

    // One's complement over 16-bit words, with the checksum field included in the span: a valid header
    // sums to zero. RFC 791 §3.1 defines both the field and the fold.
    private static ushort OnesComplementSum(ReadOnlySpan<byte> data)
    {
        uint sum = 0;
        for (var i = 0; i + 1 < data.Length; i += 2)
            sum += BinaryPrimitives.ReadUInt16BigEndian(data.Slice(i, 2));
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)(~sum & 0xFFFF);
    }

    private void Touch(Flow flow, byte proto, ReadOnlySpan<byte> packet, int ihl, uint remote)
    {
        flow.LastSeen = _now();
        flow.LastRemote = remote;
        flow.Packets++;
        if (proto == TcpProto && packet.Length >= ihl + 14)
        {
            var flags = packet[ihl + 13];
            if ((flags & 0x05) != 0) flow.Closing = true;
        }
    }

    private static bool IsMappedQuery(byte proto, ReadOnlySpan<byte> packet, int ihl, bool reply)
    {
        if (proto != IcmpProto) return true;
        if (packet.Length < ihl + 8) return false;
        var type = packet[ihl];
        return reply
            ? type is IcmpEchoReply or IcmpTimestampReply
            : type is IcmpEchoRequest or IcmpTimestampRequest;
    }

    // For ICMP a query's Identifier occupies the place a port would (RFC 5508 REQ-1 wants that
    // mapping to be external-host independent, which is what MapKey gives it), so it is read and
    // written as the port of the flow. An ICMP error carries no such field and is not mapped at all.
    private static bool TryReadPorts(ReadOnlySpan<byte> packet, int ihl, byte proto,
        out ushort srcPort, out ushort dstPort)
    {
        srcPort = 0;
        dstPort = 0;
        if (proto == IcmpProto)
        {
            if (packet.Length < ihl + 8) return false;
            var id = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ihl + 4, 2));
            srcPort = id;
            dstPort = id;
            return true;
        }
        if (packet.Length < ihl + 4) return false;
        srcPort = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ihl, 2));
        dstPort = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ihl + 2, 2));
        return true;
    }

    // ICMP has a single identifier where a port pair would be, so there is no source or destination
    // to choose between; TCP and UDP have both and the caller says which one it means.
    private static void WritePort(Span<byte> packet, int ihl, byte proto, ushort port, bool destination)
    {
        var offset = proto == IcmpProto ? ihl + 4 : ihl + (destination ? 2 : 0);
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(offset, 2), port);
    }

    private static uint ReadAddr(ReadOnlySpan<byte> packet, int offset)
        => BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(offset, 4));

    private static void WriteAddr(Span<byte> packet, int offset, uint value)
        => BinaryPrimitives.WriteUInt32BigEndian(packet.Slice(offset, 4), value);

    public static string FormatAddress(uint addr)
        => $"{addr >> 24}.{(addr >> 16) & 0xFF}.{(addr >> 8) & 0xFF}.{addr & 0xFF}";

    public static uint ParseAddress(string dotted)
    {
        var parts = dotted.Split('.');
        if (parts.Length != 4) throw new FormatException($"not a dotted IPv4 address: {dotted}");
        uint value = 0;
        foreach (var part in parts)
            value = (value << 8) | byte.Parse(part);
        return value;
    }

    // An operator writes a prefix length; this project carries the four octets read big-endian, so /24
    // becomes 0xFFFFFF00. The /0 answer is spelled out because a shift by 32 is a shift by 0 under C#'s
    // shift-count masking, which would make the default route read as a host route.
    public static uint MaskFromPrefix(int prefix)
    {
        if (prefix is < 0 or > 32) return 0;
        return prefix == 0 ? 0 : 0xFFFFFFFFu << (32 - prefix);
    }

    public void Sweep()
    {
        var now = _now();
        foreach (var (key, flow) in _flows)
        {
            var idle = TimeoutFor(key.Proto, flow.Closing);
            if (now - flow.LastSeen < idle) continue;
            if (!_flows.TryRemove(key, out _)) continue;
            _rev.TryRemove(new RevKey(key.Proto, flow.NatPort), out _);
            Expired?.Invoke(key, flow.NatPort, idle);
        }
        // A record is only ever asked for by a fragment of the same datagram, and a datagram whose
        // remaining fragments have not arrived inside the reassembly window is not going to be reassembled
        // by anyone, so the record has nothing left to answer for.
        foreach (var (key, val) in _frag)
        {
            if (now - val.Expires < FragmentWindow) continue;
            _frag.TryRemove(key, out _);
        }
    }

    public int FragmentCount => _frag.Count;

    public event Action<MapKey, ushort, TimeSpan>? Expired;

    private TimeSpan TimeoutFor(byte proto, bool closing) => proto switch
    {
        TcpProto => closing ? TcpTransitoryIdle : TcpEstablishedIdle,
        UdpProto => _udpIdle,
        _ => IcmpIdle,
    };

    public readonly record struct MapKey(byte Proto, uint ClientIp, ushort ClientPort);

    public readonly record struct RevKey(byte Proto, ushort NatPort);

    // RFC 791 §3.2: the fields a receiving host reassembles on. None of them is a port, which is exactly
    // why a fragment behind the first can still be placed once the first one has been mapped.
    public readonly record struct FragKey(byte Proto, uint Src, uint Dst, ushort Id);

    // Which half of the header to rewrite and with what. The port of the flow is not carried here: a
    // non-first fragment has no transport header at its offset, so the address is all there is to write.
    private record FragVal(NatAction Action, int Offset, uint NewAddr, DateTime Expires = default);

    public sealed class Flow
    {
        public MapKey Key { get; }
        public ushort NatPort { get; }
        public DateTime LastSeen;
        public uint LastRemote;
        public long Packets;
        public bool Closing;

        public Flow(MapKey key, ushort natPort, uint remote, DateTime now)
        {
            Key = key;
            NatPort = natPort;
            LastRemote = remote;
            LastSeen = now;
        }
    }
}
