using System.Buffers.Binary;
using System.Text;

namespace Router;

// The values are the ones RFC 2132 §9.6 lists for the message type option.
public enum DhcpKind { Discover = 1, Offer = 2, Request = 3, Decline = 4, Ack = 5, Nak = 6, Release = 7, Inform = 8 }

public static class DhcpPorts
{
    // RFC 2131 §4.1: "DHCP messages from a client to a server are sent to the 'DHCP server' port (67),
    // and DHCP messages from a server to a client are sent to the 'DHCP client' port (68)." A reply that
    // goes back to a relay agent instead of to a client stays on 67 - see Destination().
    public const ushort ServerPort = 67;
    public const ushort ClientPort = 68;
}

// A client as the server sees it. RFC 2131 §4.2 is explicit - "If the client supplies a 'client
// identifier', the client MUST use the same 'client identifier' in all subsequent messages, and the
// server MUST use that identifier to identify the client" - so option 61 wins when it is present and
// the hardware address is what is left when it is not. The two never share a lease, even on one NIC.
public sealed record DhcpClientKey(byte[] Raw, bool FromOption)
{
    public string Hex => Convert.ToHexString(Raw);
    public override string ToString() => Hex;
}

public sealed class DhcpLease
{
    public required DhcpClientKey Client { get; init; }

    // The subnet the lease was taken from, which for a relayed request is the relay agent's and not this
    // host's. Two scopes can hold a lease for the same client, so the pair is what identifies one.
    public required uint Network { get; init; }

    public required uint Address { get; init; }
    public string? HostName { get; set; }
    public DateTime Expires;
}

// One subnet this server can lease into. A client that reaches the server through a relay agent is not
// on the interface the socket is bound to, so everything that has to hold from the client's own subnet -
// the mask, the pool, the router and resolver it is pointed at - comes from the scope instead.
public sealed record DhcpScope
{
    public required uint Network { get; init; }
    public required uint SubnetMask { get; init; }
    public required uint PoolStart { get; init; }
    public required int PoolCount { get; init; }

    // Options 3 and 6. On the LAN side one host is both the client's router and its resolver, so the
    // default scope uses its own address for both; a relayed subnet is on the far side of the relay
    // agent and has to be told what to point at.
    public required uint Router { get; init; }
    public required uint Dns { get; init; }

    public uint BroadcastAddress => Network | ~SubnetMask;

    // The match that picks a scope for a relayed request: RFC 2131 §4.3.1 chooses the new address "based
    // on the subnet from which the message was received (if 'giaddr' is 0) or on the address of the relay
    // agent that forwarded the message ('giaddr' when not 0)".
    public bool Contains(uint addr) => (addr & SubnetMask) == Network;

    public bool InPool(uint addr)
    {
        var offset = (long)addr - PoolStart;
        return offset >= 0 && offset < PoolCount;
    }

    // <cidr>,<pool>/<count>,<router>[,<dns>], the shape one --scope takes. The pool has to sit inside the
    // scope's subnet for the same reason --pool does: an address the client cannot reach from the network
    // it is on is not a lease. The router is held to the same rule because option 3 is the next hop the
    // client puts on its own link. The resolver is not, because this program's resolver is deliberately on
    // the far side of the relay and reached by routing - which is why it defaults to the listening address.
    public static bool TryParse(string text, uint listeningAddress, out DhcpScope scope, out string why)
    {
        scope = null!;
        why = "";
        var parts = text.Split(',');
        if (parts.Length is < 3 or > 4)
        {
            why = "wants <cidr>,<pool>/<count>,<router>[,<dns>]";
            return false;
        }

        var cidr = parts[0].Split('/');
        if (cidr.Length != 2 || !int.TryParse(cidr[1], out var prefix) || prefix is < 0 or > 32
            || !TryAddress(cidr[0], out var written))
        {
            why = $"'{parts[0]}' is not an <ipv4>/<prefix>";
            return false;
        }
        // The host bits of a written address are the operator's shorthand for the subnet it is in, not a
        // second constraint, so 192.168.10.55/26 and 192.168.10.0/26 name the same scope.
        var mask = NatTable.MaskFromPrefix(prefix);
        var network = written & mask;

        var pool = parts[1].Split('/');
        if (pool.Length != 2 || !int.TryParse(pool[1], out var poolCount) || poolCount <= 0
            || !TryAddress(pool[0], out var poolStart))
        {
            why = $"'{parts[1]}' is not a <pool>/<count>";
            return false;
        }
        if (!DhcpConfig.PoolFitsSubnet(poolStart, poolCount, network, mask))
        {
            why = $"pool {parts[1]} is outside {NatTable.FormatAddress(network)}/{prefix}";
            return false;
        }

        if (!TryAddress(parts[2], out var router) || (router & mask) != network)
        {
            why = $"'{parts[2]}' is not an address inside {NatTable.FormatAddress(network)}/{prefix}";
            return false;
        }

        var dns = listeningAddress;
        if (parts.Length == 4 && !TryAddress(parts[3], out dns))
        {
            why = $"'{parts[3]}' is not an address";
            return false;
        }

        scope = new DhcpScope
        {
            Network = network,
            SubnetMask = mask,
            PoolStart = poolStart,
            PoolCount = poolCount,
            Router = router,
            Dns = dns,
        };
        return true;
    }

    private static bool TryAddress(string text, out uint address)
    {
        try
        {
            address = NatTable.ParseAddress(text);
            return true;
        }
        catch (Exception ex) when (ex is FormatException or ArgumentNullException)
        {
            address = 0;
            return false;
        }
    }
}

public sealed record DhcpConfig
{
    // The address the listener is bound to, and so the address a reply was received on. RFC 2131 §4.1
    // tells a server that received a message through a relay agent to "choose an address from the
    // interface on which the message was recieved as the 'server identifier'", which is this one for
    // every scope, and RFC 2132 §9.7 fixes option 54's length at "4" - one dotted-form address. On the
    // LAN side it is also the client's router (option 3) and resolver (option 6), because this host
    // really is both.
    public required uint ServerAddress { get; init; }
    public required uint SubnetMask { get; init; }
    public required uint PoolStart { get; init; }
    public required int PoolCount { get; init; }
    public TimeSpan LeaseTime { get; init; } = TimeSpan.FromHours(24);

    // Subnets on the far side of a relay agent, in the order they were configured: the first whose
    // subnet contains 'giaddr' answers, and a relayed request that matches none is left unanswered.
    public IReadOnlyList<DhcpScope> RelayScopes { get; init; } = Array.Empty<DhcpScope>();

    // The subnet this host's own interface is on, which is the scope for every request that arrives with
    // 'giaddr' zero.
    public DhcpScope LocalScope => new()
    {
        Network = ServerAddress & SubnetMask,
        SubnetMask = SubnetMask,
        PoolStart = PoolStart,
        PoolCount = PoolCount,
        Router = ServerAddress,
        Dns = ServerAddress,
    };

    public DhcpScope? ScopeFor(uint giAddr) => giAddr == 0
        ? LocalScope
        : RelayScopes.FirstOrDefault(scope => scope.Contains(giAddr));

    // Whether a whole range stays inside the subnet the LAN-side interface belongs to. A pool that
    // leaves the subnet would be handed out and then be unreachable through the interface that served
    // it, which is a configuration mistake rather than a lease the client can use. The end of the range
    // is compared in a signed space because these addresses are the four octets read big-endian, where
    // a pool near the top of a /8 would otherwise wrap past the broadcast address and read as fitting.
    public static bool PoolFitsSubnet(uint start, int count, uint serverAddress, uint mask)
    {
        var network = serverAddress & mask;
        var broadcast = network | ~mask;
        return start >= network && start <= broadcast && (long)start + count - 1 <= broadcast;
    }

    // The room a subnet has for a pool: everything between its network address and its broadcast
    // address except those two. A subnet with none reads as a refusal - which is what the caller
    // checks for - rather than as a count that has wrapped.
    public static int PoolRoom(uint serverAddress, uint mask)
    {
        var network = serverAddress & mask;
        return (int)((network | ~mask) - network - 1);
    }
}

// The packet itself, with nothing about sockets or clocks in it.
//
// RFC 2131 §2 is titled "Protocol Summary" and says "Figure 1 gives the format of a DHCP message and
// table 1 describes each of the fields in the DHCP message" - the BOOTP layout, so these offsets are
// BOOTP's: op 0, htype 1, hlen 2, hops 3, xid 4, secs 8, flags 10, ciaddr 12, yiaddr 16, siaddr 20,
// giaddr 24, chaddr 28 (16 octets), sname 44 (64), file 108 (128), options 236. The first four octets
// of 'options' hold the magic cookie (RFC 2131 §3), which is what makes the message DHCP rather than
// plain BOOTP, so a conforming message is at least 240 octets before any option appears.
public static class DhcpFormat
{
    public const int HeaderLength = 240;
    // "The first four octets of the 'options' field... contain the (decimal) values 99, 130, 83 and 99"
    // - RFC 2131 §3. What separates DHCP from the BOOTP message it is laid out like.
    public const uint MagicCookie = 0x63825363;
    private const int MaxHwAddress = 16;

    public const byte Pad = 0;
    public const byte End = 255;
    public const byte SubnetMask = 1;
    public const byte Router = 3;
    public const byte Dns = 6;
    public const byte HostName = 12;
    public const byte DomainName = 15;
    public const byte Broadcast = 28;
    public const byte RequestedAddress = 50;
    public const byte LeaseTime = 51;
    public const byte MessageType = 53;
    public const byte ServerId = 54;
    public const byte ParameterRequestList = 55;
    public const byte Message = 56;
    public const byte ClientIdentifier = 61;

    public sealed class Request
    {
        public DhcpKind Kind;
        public uint Xid;
        public bool BroadcastFlag;
        public uint CiAddr;

        // The relay agent's address. Non-zero means the client is on a subnet the server is not bound to,
        // and it is both how the reply finds its way back and how the scope is chosen.
        public uint GiAddr;

        public uint RequestedAddress;
        public string? HostName;
        public byte Htype;
        public byte[] HardwareAddress = Array.Empty<byte>();
        public byte[]? ClientId;
        public List<byte> RequestedOptions = new();
        public DhcpClientKey Key => ClientId is { Length: > 0 } id
            ? new DhcpClientKey(id, true)
            : new DhcpClientKey(HardwareAddress, false);
    }

    public static bool TryParse(ReadOnlySpan<byte> message, out Request request)
    {
        request = new Request();
        if (message.Length < HeaderLength) return false;
        if (BinaryPrimitives.ReadUInt32BigEndian(message.Slice(236, 4)) != MagicCookie) return false;
        if (message[0] != 1) return false; // only BOOTREQUEST reaches a server

        request.Xid = BinaryPrimitives.ReadUInt32BigEndian(message.Slice(4, 4));
        // RFC 2131 §2.1: "The leftmost bit is defined as the BROADCAST (B) flag."
        request.BroadcastFlag = (message[10] & 0x80) != 0;
        request.CiAddr = BinaryPrimitives.ReadUInt32BigEndian(message.Slice(12, 4));
        // BOOTP offset 24. RFC 2131 §2's table calls it the "Relay agent IP address, used in booting via
        // a relay agent", and it is the agent that fills it in, never the client.
        request.GiAddr = BinaryPrimitives.ReadUInt32BigEndian(message.Slice(24, 4));
        request.Htype = message[1];
        var hlen = message[2];
        if (hlen is > 0 and <= MaxHwAddress)
            request.HardwareAddress = message.Slice(28, hlen).ToArray();

        var kind = 0;
        for (var i = HeaderLength; i < message.Length;)
        {
            var tag = message[i];
            if (tag == End) break;
            if (tag == Pad) { i++; continue; }
            if (i + 2 > message.Length) break;
            var length = message[i + 1];
            if (i + 2 + length > message.Length) break; // a truncated option is not a parseable one
            var value = message.Slice(i + 2, length);
            switch (tag)
            {
                case MessageType when length == 1:
                    kind = value[0];
                    break;
                case RequestedAddress when length == 4:
                    request.RequestedAddress = BinaryPrimitives.ReadUInt32BigEndian(value);
                    break;
                case HostName when length > 0:
                    request.HostName = Encoding.ASCII.GetString(value);
                    break;
                case ClientIdentifier when length > 0:
                    request.ClientId = value.ToArray();
                    break;
                case ParameterRequestList:
                    request.RequestedOptions.AddRange(value.ToArray());
                    break;
            }
            i += 2 + length;
        }

        // Without option 53 this is BOOTP, and a lease concept does not exist for it: replying would
        // hand out an address nothing will ever time out or rebind.
        if (kind == 0) return false;
        request.Kind = (DhcpKind)kind;
        return true;
    }

    // Options are handed in already valued, because ordering is the server's business: RFC 2132 §9.8
    // says a server "MUST try to insert the requested options in the order requested by the client"
    // when the client sends a Parameter Request List.
    public static byte[] BuildReply(Request request, DhcpKind kind, uint yiaddr, uint serverAddress,
        IReadOnlyList<(byte Tag, byte[] Value)> options)
    {
        var payload = new List<byte> { MessageType, 1, (byte)kind };
        payload.Add(ServerId);
        payload.Add(4);
        payload.AddRange(Address(serverAddress));
        foreach (var (tag, value) in options)
        {
            payload.Add(tag);
            payload.Add((byte)value.Length);
            payload.AddRange(value);
        }
        payload.Add(End);

        var message = new byte[HeaderLength + payload.Count];
        message[0] = 2; // BOOTREPLY
        message[1] = request.Htype;
        message[2] = (byte)request.HardwareAddress.Length;
        BinaryPrimitives.WriteUInt32BigEndian(message.AsSpan(4, 4), request.Xid);
        // The flag is echoed rather than re-decided: it is how the client asked to be reached, and a
        // client that set it must not be unicasted to.
        if (request.BroadcastFlag) message[10] = 0x80;
        BinaryPrimitives.WriteUInt32BigEndian(message.AsSpan(12, 4), kind is DhcpKind.Ack or DhcpKind.Nak ? request.CiAddr : 0);
        BinaryPrimitives.WriteUInt32BigEndian(message.AsSpan(16, 4), yiaddr);
        // The reply has to carry the relay agent's address back: it is how the agent chooses the interface
        // to deliver on, and RFC 1542 §4.1.2 says a BOOTREPLY whose 'giaddr' "does not match one of the
        // relay agent's directly-connected logical interfaces" MUST be silently discarded.
        BinaryPrimitives.WriteUInt32BigEndian(message.AsSpan(24, 4), request.GiAddr);
        request.HardwareAddress.AsSpan().CopyTo(message.AsSpan(28));
        BinaryPrimitives.WriteUInt32BigEndian(message.AsSpan(236, 4), MagicCookie);
        payload.CopyTo(message, HeaderLength);
        return message;
    }

    public static byte[] Address(uint addr)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, addr);
        return bytes;
    }

    // The lease as the client reads it, in wire order. A client that is given an address and a resolver
    // but no option 3 can reach this host and nothing past it, so this is the line that separates a
    // lease problem from a forwarding one.
    public static string DescribeOptions(ReadOnlySpan<byte> message)
    {
        if (message.Length < HeaderLength) return "(short)";
        var parts = new List<string>();
        for (var i = HeaderLength; i < message.Length;)
        {
            var tag = message[i];
            if (tag == End) break;
            if (tag == Pad) { i++; continue; }
            if (i + 2 > message.Length) { parts.Add("truncated"); break; }
            var length = message[i + 1];
            if (i + 2 + length > message.Length) { parts.Add("truncated"); break; }
            parts.Add($"{tag}={DescribeOption(tag, message.Slice(i + 2, length))}");
            i += 2 + length;
        }
        return string.Join(' ', parts);
    }

    private static string DescribeOption(byte tag, ReadOnlySpan<byte> value) => tag switch
    {
        SubnetMask or Router or Dns or Broadcast or RequestedAddress or ServerId when value.Length == 4
            => NatTable.FormatAddress(BinaryPrimitives.ReadUInt32BigEndian(value)),
        LeaseTime when value.Length == 4 => $"{BinaryPrimitives.ReadUInt32BigEndian(value)}s",
        MessageType when value.Length == 1 => ((DhcpKind)value[0]).ToString(),
        _ => Convert.ToHexString(value),
    };

    public static byte[] Seconds(uint value)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        return bytes;
    }
}

// The pool and its leases. No sockets: Handle() takes the request bytes and returns the reply bytes
// plus where they have to go, which is what tests/servcheck drives directly.
public sealed class DhcpServer
{
    private readonly DhcpConfig _config;
    private readonly Func<DateTime> _now;
    // Keyed by the scope as well as the client: a machine seen through two relay agents is on two subnets
    // and needs an address in each, so one lease cannot follow it between them.
    private readonly Dictionary<(uint Network, string Client), DhcpLease> _byClient = new();
    private readonly Dictionary<uint, DhcpLease> _byAddress = new();
    // Addresses a client has said are already in use elsewhere on the segment (DHCPDECLINE, RFC 2131
    // §4.3.3 tells the server not to hand the address out again). They are held until they expire from
    // the pool rather than remembered forever: a conflict is usually a stale lease on the other host.
    private readonly Dictionary<uint, DateTime> _conflicted = new();

    public DhcpServer(DhcpConfig config, Func<DateTime>? now = null)
    {
        _config = config;
        _now = now ?? (() => DateTime.UtcNow);
    }

    public int LeaseCount => _byClient.Count;
    public IEnumerable<DhcpLease> Leases => _byClient.Values;
    public uint PoolStart => _config.PoolStart;
    public int PoolCount => _config.PoolCount;
    public IReadOnlyList<DhcpScope> RelayScopes => _config.RelayScopes;

    // What makes a leased device reachable by a name: the hostname it sent in option 12, looked up
    // against the address its lease holds. Compared without case, because a client types its host name
    // and a resolver lowercases the query.
    public uint? AddressOfHostName(string name)
    {
        foreach (var lease in _byClient.Values)
            if (lease.HostName is { Length: > 0 } host
                && string.Equals(host, name, StringComparison.OrdinalIgnoreCase))
                return lease.Address;
        return null;
    }

    public event Action<DhcpLease>? Leased;

    // A relayed request whose 'giaddr' is in no configured scope. Reported rather than answered from the
    // wrong subnet, which would hand the client an address it cannot use.
    public event Action<uint>? RelayWithoutScope;

    public bool TryReply(ReadOnlySpan<byte> request, out DhcpReply? reply)
    {
        reply = null;
        if (!DhcpFormat.TryParse(request, out var parsed)) return false;

        // RFC 2131 §4.3.1 names the subnet the address comes from before anything is allocated, so a
        // relayed request that matches no scope is left unanswered rather than answered from this host's.
        var scope = _config.ScopeFor(parsed.GiAddr);
        if (scope is null)
        {
            RelayWithoutScope?.Invoke(parsed.GiAddr);
            return false;
        }

        switch (parsed.Kind)
        {
            case DhcpKind.Discover:
                reply = Offer(parsed, scope);
                return true;
            case DhcpKind.Request:
                reply = Confirm(parsed, scope);
                return true;
            case DhcpKind.Decline:
                Decline(parsed, scope);
                return false;
            case DhcpKind.Release:
                Release(parsed, scope);
                return false;
            default:
                // INFORM (the client already has its address and wants parameters) and any other kind
                // are left unanswered; the traffic this project cares about still flows.
                return false;
        }
    }

    public DhcpLease? LeaseFor(uint address) => _byAddress.TryGetValue(address, out var lease) ? lease : null;

    public void Sweep()
    {
        var now = _now();
        foreach (var lease in _byAddress.Values.Where(l => l.Expires <= now).ToArray())
        {
            _byAddress.Remove(lease.Address);
            _byClient.Remove((lease.Network, lease.Client.Hex));
        }
        foreach (var (addr, until) in _conflicted.Where(kv => kv.Value <= now).ToArray())
            _conflicted.Remove(addr);
    }

    private DhcpReply Offer(DhcpFormat.Request request, DhcpScope scope)
    {
        var lease = ExistingOrNew(request, scope, request.RequestedAddress);
        var options = Parameters(lease, scope, request);
        var bytes = DhcpFormat.BuildReply(request, DhcpKind.Offer, lease.Address, _config.ServerAddress, options);
        return Destination(request, DhcpKind.Offer, bytes);
    }

    private DhcpReply Confirm(DhcpFormat.Request request, DhcpScope scope)
    {
        // The client names the address it wants in option 50 when it is picking one up, and sends none
        // when it is renewing the address it already holds in ciaddr (RFC 2131 §4.3.2 walks both).
        var address = request.RequestedAddress != 0 ? request.RequestedAddress : request.CiAddr;

        // Two ways the request is not honourable: the address is outside the scope's pool, or the pool has
        // it on somebody else's lease. Both get the same answer, because the client's only remedy is the
        // same - go back to DISCOVER. An address that is perfectly good in another scope is still refused
        // here, because the client could not use it from this subnet.
        if (request.RequestedAddress != 0 && !scope.InPool(request.RequestedAddress))
            return Nak(request, "not in pool");
        if (request.RequestedAddress != 0
            && _byAddress.TryGetValue(request.RequestedAddress, out var held)
            && held.Client.Hex != request.Key.Hex)
            return Nak(request, "leased to another client");
        // The address this host answers on is in use by this host, so confirming it would hand the
        // client a conflict; a NAK sends it back to DISCOVER, which is the same remedy the two
        // refusals above give.
        if (request.RequestedAddress != 0 && IsOurs(scope, request.RequestedAddress))
            return Nak(request, "this host's address");

        var lease = ExistingOrNew(request, scope, address);
        var options = Parameters(lease, scope, request);
        var bytes = DhcpFormat.BuildReply(request, DhcpKind.Ack, lease.Address, _config.ServerAddress, options);
        return Destination(request, DhcpKind.Ack, bytes);
    }

    private DhcpReply Nak(DhcpFormat.Request request, string reason)
    {
        var bytes = DhcpFormat.BuildReply(request, DhcpKind.Nak, 0, _config.ServerAddress,
            new (byte, byte[])[] { (DhcpFormat.Message, Encoding.ASCII.GetBytes(reason)) });
        return Destination(request, DhcpKind.Nak, bytes);
    }

    private void Decline(DhcpFormat.Request request, DhcpScope scope)
    {
        var address = request.RequestedAddress;
        if (address == 0) return;
        _conflicted[address] = _now() + _config.LeaseTime;
        var key = (scope.Network, request.Key.Hex);
        if (_byClient.TryGetValue(key, out var lease) && lease.Address == address)
        {
            _byAddress.Remove(address);
            _byClient.Remove(key);
        }
    }

    private void Release(DhcpFormat.Request request, DhcpScope scope)
    {
        var key = (scope.Network, request.Key.Hex);
        if (_byClient.TryGetValue(key, out var lease))
        {
            _byAddress.Remove(lease.Address);
            _byClient.Remove(key);
        }
    }

    private DhcpLease ExistingOrNew(DhcpFormat.Request request, DhcpScope scope, uint preferred)
    {
        var now = _now();
        var key = (scope.Network, request.Key.Hex);
        if (_byClient.TryGetValue(key, out var existing))
        {
            if (preferred == 0 || preferred == existing.Address)
            {
                existing.Expires = now + _config.LeaseTime;
                existing.HostName = request.HostName ?? existing.HostName;
                return existing;
            }
            // It is asking for a different address than the one it holds: give it that one if the pool
            // allows, and move the lease over rather than leaving a second entry for the same client.
            _byAddress.Remove(existing.Address);
            _byClient.Remove(key);
        }

        var address = ChooseAddress(scope, preferred);
        var lease = new DhcpLease
        {
            Client = request.Key,
            Network = scope.Network,
            Address = address,
            HostName = request.HostName,
            Expires = now + _config.LeaseTime,
        };
        _byClient[key] = lease;
        _byAddress[address] = lease;
        Leased?.Invoke(lease);
        return lease;
    }

    // The two addresses a scope points its clients at are this server's own when the scope was derived
    // from a local interface, and are still not the server's to lease when they belong to a relayed
    // subnet's router: either way the client would be handed the address its own answer depends on.
    private static bool IsOurs(DhcpScope scope, uint address)
        => address == scope.Router || address == scope.Dns;

    private uint ChooseAddress(DhcpScope scope, uint preferred)
    {
        // Leasing the subnet's router or resolver would take away the address options 3 and 6 point the
        // client at, and on this host's own subnet both of those are its interface address. The test
        // belongs on both paths, because the client names an address in option 50 whenever it is holding
        // a lease from another server, and this host's own address is inside a pool that starts below it.
        bool Free(uint address) => !IsOurs(scope, address)
            && !_byAddress.ContainsKey(address) && !_conflicted.ContainsKey(address);

        // The address the client asked for wins when the scope owns it and nothing else holds it: a
        // client rebooting into INIT-REBOOT has to get its old address back or it loses connectivity for
        // the length of a lease.
        if (preferred != 0 && scope.InPool(preferred) && Free(preferred))
            return preferred;

        for (uint offset = 0; offset < (uint)scope.PoolCount; offset++)
        {
            var candidate = scope.PoolStart + offset;
            if (!scope.Contains(candidate)) continue;
            if (!Free(candidate)) continue;
            return candidate;
        }
        throw new InvalidOperationException(
            $"DHCP pool {NatTable.FormatAddress(scope.PoolStart)}+{scope.PoolCount} has no free address");
    }

    // The scope's whole parameter set goes out, ordered by whatever the client listed first: RFC 2132
    // §9.8 obliges a server to "try to insert the requested options in the order requested by the
    // client", which is a rule about order, not a licence to withhold the address's subnet mask or the
    // lease time. Options the client asks for that this scope has no value for are left out rather than
    // answered with a wrong one.
    private List<(byte, byte[])> Parameters(DhcpLease lease, DhcpScope scope, DhcpFormat.Request request)
    {
        // A list, not a dictionary: the byte order of a reply is what a client sees, and an unordered
        // collection would make the same lease produce different bytes on different runs.
        var available = new List<(byte Tag, byte[] Value)>
        {
            (DhcpFormat.SubnetMask, DhcpFormat.Address(scope.SubnetMask)),
            (DhcpFormat.Router, DhcpFormat.Address(scope.Router)),
            (DhcpFormat.Dns, DhcpFormat.Address(scope.Dns)),
            (DhcpFormat.LeaseTime, DhcpFormat.Seconds((uint)_config.LeaseTime.TotalSeconds)),
            (DhcpFormat.Broadcast, DhcpFormat.Address(scope.BroadcastAddress)),
        };
        if (lease.HostName is { Length: > 0 } name)
            available.Add((DhcpFormat.HostName, Encoding.ASCII.GetBytes(name)));

        var ordered = new List<(byte, byte[])>();
        var taken = new HashSet<byte>();
        foreach (var tag in request.RequestedOptions)
        {
            var match = available.FirstOrDefault(entry => entry.Tag == tag);
            if (match.Tag != 0 && taken.Add(tag))
                ordered.Add((match.Tag, match.Value));
        }
        foreach (var (tag, value) in available)
            if (taken.Add(tag))
                ordered.Add((tag, value));
        return ordered;
    }

    private static DhcpReply Destination(DhcpFormat.Request request, DhcpKind kind, byte[] bytes)
    {
        // RFC 2131 §4.1 puts the relay agent first: "If the 'giaddr' field in a DHCP message from a client
        // is non-zero, the server sends any return messages to the 'DHCP server' port on the BOOTP relay
        // agent whose address appears in 'giaddr'". Any return message, so a NAK goes to the agent as well,
        // and the client's BROADCAST flag rides along in the reply for the agent to act on - RFC 1542 §5.4
        // tells the server it "MUST preserve the state of the BROADCAST flag so that the relay agent can
        // correctly act upon it".
        if (request.GiAddr != 0)
            return new DhcpReply(bytes, request.GiAddr, false, DhcpPorts.ServerPort, kind)
            {
                Client = request.Key,
            };

        // With no agent in the path, §4.1 leaves three cases a UDP socket can act on: OFFER and ACK are
        // unicasted to a client that already has an address in ciaddr, the limited broadcast answers a
        // client that has nothing and asked for broadcast, and "in all cases, when 'giaddr' is zero, the
        // server broadcasts any DHCPNAK messages to 0xffffffff" - a NAK is never unicasted, because the
        // address in ciaddr is the one being refused. The fourth case §4.1 lists, unicasting a reply to a
        // client with no ciaddr at its hardware address plus the yiaddr just offered, is RFC 1542 §5.4's
        // link-layer delivery; the broadcast it permits "if unicasting is not possible" is what this
        // listener does.
        var canUnicast = request.CiAddr != 0 && kind is DhcpKind.Offer or DhcpKind.Ack;
        var broadcast = request.BroadcastFlag || !canUnicast;
        return new DhcpReply(bytes, broadcast ? 0xFFFFFFFF : request.CiAddr, broadcast, DhcpPorts.ClientPort, kind)
        {
            Client = request.Key,
        };
    }
}

public sealed record DhcpReply(byte[] Bytes, uint DestinationIp, bool Broadcast, ushort DestinationPort, DhcpKind Kind)
{
    public required DhcpClientKey Client { get; init; }
}
