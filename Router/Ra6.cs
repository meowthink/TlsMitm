using System.Buffers.Binary;
using System.Net;

namespace Router;

// Everything one Router Advertisement carries, assembled from the delegation the LAN was given. The
// lifetimes are the remaining ones, as a host counts them down on its own clock; this type only writes
// what it is handed.
public sealed record RaAdvertisement
{
    // RFC 4861 §4.6.1: the router's link-layer address, so a host can reach it without first asking.
    public required byte[] LinkLayerAddress { get; init; }

    public required Dhcp6Prefix Prefix { get; init; }
    public required uint PreferredLifetime { get; init; }
    public required uint ValidLifetime { get; init; }

    // RFC 4861 §4.6.4: the MTU hosts on this link should use. Taken from the WAN, so a packet a client
    // sends is never larger than the link that has to carry it next. Zero means the WAN's MTU could not
    // be read, and then the option is left out entirely.
    public required uint Mtu { get; init; }

    // RFC 4861 §4.2: seconds a host may keep this router as its default; zero says "not a default router".
    public required uint RouterLifetime { get; init; }

    // RFC 8106 §5.1: the resolver the DHCPv6 Reply named travels in the same advertisement that hands out
    // the prefix, because a host that configures itself from a Router Advertisement has no DHCPv6
    // conversation to learn it from.
    public IReadOnlyList<byte[]> RecursiveDns { get; init; } = Array.Empty<byte[]>();
    public required uint DnsLifetime { get; init; }

    // RFC 8781 §4: the NAT64 prefix hosts on this link synthesize against. Null leaves the option out,
    // which is what a run without --pref64 advertises: the prefix the option names is the one the answers
    // were built with, and a host that synthesizes against a prefix with no translator behind it forms
    // addresses that go nowhere.
    public Pref64Advertisement? Pref64 { get; init; }
}

// One PREF64 option's worth of configuration. RFC 8781 §5 lets the option "appear more than once in an RA
// (e.g., when gracefully renumbering the network from one NAT64 prefix to another)"; this router has the
// one prefix its DNS64 synthesizes with, so the advertisement carries the one option and nothing has to
// decide an order between them.
public sealed record Pref64Advertisement(Pref64Config Prefix, uint LifetimeSeconds);

// The ICMPv6 Router Solicitation and Router Advertisement this router speaks on its LAN side
// (RFC 4861 §4.2, §6.1.1, §6.2), plus the schedule that says when the next one goes out (§6.2.4,
// §6.2.6). No socket and no clock is held here: the caller supplies time and randomness.
public static class Ra6
{
    // RFC 4861 §4.1 and §4.2: the ICMPv6 type numbers.
    public const byte Solicitation = 133;
    public const byte Advertisement = 134;

    // RFC 4861 §6.1.1 and §6.1.2: "IP Hop Limit MUST be set to 255". The Cur Hop Limit field of an
    // advertisement (§4.2) is a different number: the default a host puts on its own packets, and 64 is
    // the value the Assigned Numbers registry names as current.
    public const byte HopLimit = 255;
    public const byte CurHopLimit = 64;

    // RFC 4861 §4.6 and RFC 8106 §5.1.
    public const byte OptionSourceLinkLayer = 1;
    public const byte OptionPrefixInformation = 3;
    public const byte OptionMtu = 5;
    public const byte OptionRecursiveDns = 25;

    // RFC 8781 §4: "8-bit identifier of the PREF64 option type (38)".
    public const byte OptionPref64 = 38;

    // RFC 4443 §2.3: the next-header value the pseudo-header names for ICMPv6.
    private const byte Icmpv6 = 58;

    public static byte[] Build(RaAdvertisement advertisement, IPAddress source, IPAddress destination) =>
        Message(advertisement.RouterLifetime,
            Options(advertisement, advertisement.ValidLifetime, advertisement.PreferredLifetime,
                advertisement.DnsLifetime, advertisement.Pref64?.LifetimeSeconds ?? 0),
            source, destination);

    // The advertisement that takes a prefix away. RFC 4861 §6.2.5 gives a router at most
    // MAX_FINAL_RTR_ADVERTISEMENTS final advertisements with a router lifetime of zero, and
    // RFC 4862 §5.5.3(e) is what makes a host stop using the prefix: it is "advertised with a Valid
    // Lifetime of zero and a Preferred Lifetime of zero". The resolver goes the same way - RFC 8106 §5.1
    // makes a lifetime of zero mean the address is no longer to be used. PREF64 has the same signal and no
    // other one: RFC 8781 §4.1 says "A lifetime of 0 indicates that the prefix SHOULD NOT be used
    // anymore", so the withdrawal carries the option with a zero Scaled Lifetime rather than leave it out.
    public static byte[] Withdraw(RaAdvertisement advertisement, IPAddress source, IPAddress destination) =>
        Message(0, Options(advertisement, 0, 0, 0, 0), source, destination);

    // §6.1.1: a Router Solicitation is type 133, code zero, and a four-octet reserved field before its
    // options. The options are only walked to reject one that runs off the end; nothing in them changes
    // the answer, because the response is the same advertisement the periodic timer sends.
    public static bool TrySolicitation(ReadOnlySpan<byte> message, out string why)
    {
        why = "";
        if (message.Length < 8)
        {
            why = $"a Router Solicitation is at least 8 octets, this one is {message.Length}";
            return false;
        }
        if (message[0] != Solicitation)
        {
            why = $"ICMPv6 type {message[0]} is not a Router Solicitation";
            return false;
        }
        if (message[1] != 0)
        {
            why = $"ICMPv6 code {message[1]} is not zero";
            return false;
        }
        for (var offset = 8; offset < message.Length;)
        {
            if (offset + 2 > message.Length)
            {
                why = "an option runs past the end of the message";
                return false;
            }
            // RFC 4861 §4.6: an option's length field counts 8-octet units, so zero is the one value
            // that cannot describe an option and would leave the walk in place.
            var length = message[offset + 1] * 8;
            if (length == 0 || offset + length > message.Length)
            {
                why = $"option {message[offset]} claims {length} octets and {message.Length - offset} are left";
                return false;
            }
            offset += length;
        }
        return true;
    }

    // RFC 4443 §2.3: the checksum covers a pseudo-header - source, destination, the 32-bit upper-layer
    // length, three zero octets and the value 58 - followed by the message with this field zero. The
    // kernel may write its own for a raw ICMPv6 socket (RFC 3542 §11.3.1 makes it the kernel's job), but
    // an advertisement injected at the network layer carries whatever is here, so it is always computed.
    public static ushort Checksum(ReadOnlySpan<byte> message, IPAddress source, IPAddress destination)
    {
        var sum = 0u;
        sum = Add(source.GetAddressBytes(), sum);
        sum = Add(destination.GetAddressBytes(), sum);
        Span<byte> trail = stackalloc byte[8];
        BinaryPrimitives.WriteUInt32BigEndian(trail, (uint)message.Length);
        trail[7] = Icmpv6;
        sum = Add(trail, sum);
        sum = Add(message, sum);
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~sum;
    }

    // The one's complement sum of 16-bit words, with an odd trailing octet padded on the right by zero
    // (RFC 1071 §2).
    private static uint Add(ReadOnlySpan<byte> span, uint sum)
    {
        var offset = 0;
        for (; offset + 1 < span.Length; offset += 2)
            sum += BinaryPrimitives.ReadUInt16BigEndian(span.Slice(offset, 2));
        if (offset < span.Length) sum += (uint)(span[offset] << 8);
        return sum;
    }

    private static List<byte[]> Options(RaAdvertisement advertisement, uint valid, uint preferred,
        uint dnsLifetime, uint pref64Lifetime)
    {
        var options = new List<byte[]>
        {
            LinkLayer(advertisement.LinkLayerAddress),
            PrefixInformation(advertisement.Prefix, valid, preferred),
        };
        // §4.6.4: the option is optional, and a router with no MTU to name omits it rather than claiming
        // zero - a host that reads 0 has been told a nonsense link size.
        if (advertisement.Mtu != 0) options.Insert(1, Mtu(advertisement.Mtu));
        if (advertisement.RecursiveDns.Count > 0)
            options.Add(RecursiveDns(advertisement.RecursiveDns, dnsLifetime));
        if (advertisement.Pref64 is { } pref64) options.Add(Pref64Option(pref64, pref64Lifetime));
        return options;
    }

    // RFC 4861 §4.2. The eleven octets before the options are fixed; every option after them is
    // length-prefixed in 8-octet units.
    private static byte[] Message(uint routerLifetime, List<byte[]> options, IPAddress source,
        IPAddress destination)
    {
        var length = 16;
        foreach (var option in options) length += option.Length;
        var message = new byte[length];
        message[0] = Advertisement;
        message[4] = CurHopLimit;
        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(6), (ushort)routerLifetime);
        var offset = 16;
        foreach (var option in options)
        {
            option.CopyTo(message, offset);
            offset += option.Length;
        }
        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(2), Checksum(message, source, destination));
        return message;
    }

    // §4.6.1: type, length in 8-octet units, then the address padded to that unit - six octets of
    // Ethernet address in the eight the option occupies.
    private static byte[] LinkLayer(byte[] address)
    {
        var length = (2 + address.Length + 7) / 8 * 8;
        var option = new byte[length];
        option[0] = OptionSourceLinkLayer;
        option[1] = (byte)(length / 8);
        address.CopyTo(option, 2);
        return option;
    }

    // §4.6.4.
    private static byte[] Mtu(uint mtu)
    {
        var option = new byte[8];
        option[0] = OptionMtu;
        option[1] = 1;
        BinaryPrimitives.WriteUInt32BigEndian(option.AsSpan(4), mtu);
        return option;
    }

    // §4.6.2: prefix length, the on-link (L) and autonomous (A) flags, both lifetimes, and the prefix.
    // L is what makes the delegated /64 reachable through this router, and A is what lets a host form
    // its own address from it.
    private static byte[] PrefixInformation(Dhcp6Prefix prefix, uint valid, uint preferred)
    {
        var option = new byte[32];
        option[0] = OptionPrefixInformation;
        option[1] = 4;
        option[2] = prefix.Length;
        option[3] = 0x80 | 0x40;
        BinaryPrimitives.WriteUInt32BigEndian(option.AsSpan(4), valid);
        BinaryPrimitives.WriteUInt32BigEndian(option.AsSpan(8), preferred);
        prefix.Address.CopyTo(option, 16);
        return option;
    }

    // RFC 8106 §5.1: the length is "1 + 2 * (number of addresses)" in 8-octet units, then a reserved
    // field, the lifetime, and the addresses.
    private static byte[] RecursiveDns(IReadOnlyList<byte[]> servers, uint lifetime)
    {
        var option = new byte[8 + 16 * servers.Count];
        option[0] = OptionRecursiveDns;
        option[1] = (byte)(1 + 2 * servers.Count);
        BinaryPrimitives.WriteUInt32BigEndian(option.AsSpan(4), lifetime);
        for (var i = 0; i < servers.Count; i++) servers[i].CopyTo(option, 8 + 16 * i);
        return option;
    }

    // RFC 8781 §4: "The sender MUST set the length to 2" - two units of 8 octets - and the receiver "MUST
    // ignore the PREF64 option if the Length field value is not 2". The 13-bit Scaled Lifetime and the
    // 3-bit Prefix Length Code share the short that follows, and the option's last twelve octets are
    // "bits 0 - 95 of the NAT64 prefix": the whole prefix at /96, and at every shorter length the part of
    // it that fits, zero-filled past the end because Pref64::TryParse refuses a prefix with host bits set.
    private static byte[] Pref64Option(Pref64Advertisement advertisement, uint lifetimeSeconds)
    {
        var option = new byte[16];
        option[0] = OptionPref64;
        option[1] = 2;
        BinaryPrimitives.WriteUInt16BigEndian(option.AsSpan(2),
            (ushort)((ScaledLifetime(lifetimeSeconds) << 3) |
                    PrefixLengthCode(advertisement.Prefix.PrefixLength)));
        advertisement.Prefix.Prefix.GetAddressBytes().AsSpan(0, 12).CopyTo(option.AsSpan(4));
        return option;
    }

    // §4.1: "the receiver MUST multiply the Scaled Lifetime value by 8", and a router handed a nonzero
    // lifetime that is not a multiple of 8 "SHOULD round the provided value up to the nearest integer that
    // is divisible by 8 and smaller than 65536, then divide the result by 8". A nonzero one under 8 becomes
    // 1 rather than 0 - the RFC's own reason is that this "ensures that lifetimes under 8 seconds are
    // encoded as a nonzero Scaled Lifetime", and 0 is the withdrawal signal.
    public static ushort ScaledLifetime(uint lifetimeSeconds)
    {
        if (lifetimeSeconds == 0) return 0;
        return (ushort)Math.Min(((lifetimeSeconds + 7) / 8 * 8) / 8, MaxScaledLifetime);
    }

    // The 13-bit field's own width, which is also §4.1's "The maximum lifetime of the NAT64 prefix is thus
    // 65528 seconds".
    public const ushort MaxScaledLifetime = 8191;

    // §4: "The PLC field values 0, 1, 2, 3, 4, and 5 indicate the NAT64 prefix length of 96, 64, 56, 48,
    // 40, and 32 bits, respectively" - Pref64::PrefixLengths read from the far end. A length outside that
    // list would get code 6, and §4 makes the receiver "MUST ignore the PREF64 option" for any value but
    // the six, so the worst such option can do is be skipped rather than misread.
    public static int PrefixLengthCode(int prefixLength) =>
        Pref64.PrefixLengths.Length - 1 - Array.IndexOf(Pref64.PrefixLengths, prefixLength);
}

// When the next advertisement is due. RFC 4861 §6.2.4 makes the interval between multicast
// advertisements a uniform draw between MinRtrAdvInterval and MaxRtrAdvInterval, caps the first few at
// MAX_INITIAL_RTR_ADVERT_INTERVAL, and §6.2.6 gives a solicited answer its own random delay and rate
// limit. Time and randomness come from the caller, so every deadline below can be asserted.
public sealed class RaSchedule
{
    // RFC 4861 §10.
    public static readonly TimeSpan MaxRaDelay = TimeSpan.FromSeconds(0.5);
    public static readonly TimeSpan MinDelayBetweenRas = TimeSpan.FromSeconds(3);
    public static readonly TimeSpan MaxInitialInterval = TimeSpan.FromSeconds(16);
    public const int MaxInitialAdvertisements = 3;
    public const int MaxFinalAdvertisements = 3;

    private readonly Func<double> _random;
    private DateTime _next;
    private int _sent;

    // §6.2.1: MaxRtrAdvInterval defaults to 600 s and MinRtrAdvInterval to 0.33 times it. The start is
    // the moment the interface begins advertising, and the first advertisement goes at once - a host
    // that was waiting has no reason to wait for a random interval first.
    public RaSchedule(DateTime start, Func<double> random, TimeSpan? maxInterval = null)
    {
        MaxInterval = maxInterval ?? TimeSpan.FromSeconds(600);
        MinInterval = TimeSpan.FromTicks(MaxInterval.Ticks * 33 / 100);
        _random = random;
        _next = start;
    }

    public TimeSpan MaxInterval { get; }
    public TimeSpan MinInterval { get; }
    public DateTime NextDue => _next;
    public DateTime? LastMulticast { get; private set; }

    public bool Due(DateTime now) => now >= _next;

    // A multicast advertisement has gone out at this instant.
    public void Sent(DateTime now)
    {
        LastMulticast = now;
        var interval = RandomInterval();
        if (_sent < MaxInitialAdvertisements - 1 && interval > MaxInitialInterval)
            interval = MaxInitialInterval;
        _sent++;
        _next = now + interval;
    }

    // The prefix changed: §6.2.4 lets a router send up to MAX_INITIAL_RTR_ADVERTISEMENTS unsolicited
    // advertisements under the rules it uses when it starts advertising, so the burst starts again.
    public void Announce(DateTime now)
    {
        _next = now;
        _sent = 0;
    }

    // §6.2.6, for an advertisement sent in answer to a solicitation. In all cases it waits a random time
    // up to MAX_RA_DELAY_TIME; a multicast answer also gives way to the already-scheduled advertisement
    // rather than adding a second transmission, and is rate limited to one every MIN_DELAY_BETWEEN_RAS
    // after the last multicast one. A unicast answer is not a multicast advertisement, so neither limit
    // applies to it (§6.2.6 limits "consecutive Router Advertisements sent to the all-nodes multicast
    // address").
    public DateTime Solicit(DateTime now, bool multicast)
    {
        var delay = TimeSpan.FromTicks((long)(_random() * MaxRaDelay.Ticks));
        var due = now + delay;
        if (!multicast) return due;
        if (_next < due) return _next;
        if (LastMulticast is { } last && now - last < MinDelayBetweenRas)
        {
            var limited = last + MinDelayBetweenRas + delay;
            if (limited > due) due = limited;
        }
        return due;
    }

    private TimeSpan RandomInterval() =>
        TimeSpan.FromTicks(MinInterval.Ticks + (long)(_random() * (MaxInterval.Ticks - MinInterval.Ticks)));
}
