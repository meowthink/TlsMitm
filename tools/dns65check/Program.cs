using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

// Reads a type-65 (HTTPS) answer off the wire. This build's Resolve-DnsName has no HTTPS/SVCB record type
// (measured 2026-11-02: its RecordType enum stops at WINS), so finding out whether a name publishes an "ech"
// SvcParamKey means building the query and parsing the answer by hand. A target finder only - never the
// decider for a rewrite.
//
// usage: dns65check [-x] <resolver> <name> [name...]     -x dumps each answer in hex
if (args.Length < 2)
{
    Console.WriteLine("usage: dns65check [-x] <resolver> <name> [name...]");
    return 2;
}

var index = 0;
var dump = false;
if (args[0] == "-x") { dump = true; index = 1; }
if (args.Length - index < 2)
{
    Console.WriteLine("usage: dns65check [-x] <resolver> <name> [name...]");
    return 2;
}

var remote = new IPEndPoint(IPAddress.Parse(args[index]), 53);
foreach (var name in args[(index + 1)..])
    Console.WriteLine($"{name,-30} {Probe.Query(name, remote, dump)}");
return 0;

internal static class Probe
{
    public static string Query(string name, IPEndPoint remote, bool dump)
    {
        var query = Build(name);
        var sw = Stopwatch.StartNew();
        try
        {
            using var udp = new UdpClient(remote.AddressFamily);
            udp.Client.ReceiveTimeout = 3000;
            udp.Send(query, query.Length, remote);
            var from = new IPEndPoint(IPAddress.IPv6Any, 0);
            var answer = udp.Receive(ref from);
            sw.Stop();
            if (dump) Console.WriteLine($"      hex: {string.Join(" ", answer.Select(b => b.ToString("x2")))}");
            return Describe(answer, sw.ElapsedMilliseconds);
        }
        catch (Exception ex)
        {
            return $"FAILED after {sw.ElapsedMilliseconds} ms: {ex.GetType().Name}";
        }
    }

    private static string Describe(byte[] m, long ms)
    {
        if (m.Length < 12) return $"short answer ({m.Length} bytes)";
        var flags = BinaryPrimitives.ReadUInt16BigEndian(m.AsSpan(2));
        var truncated = (flags & 0x0200) != 0;
        var offset = 12;
        var questions = BinaryPrimitives.ReadUInt16BigEndian(m.AsSpan(4));
        for (var i = 0; i < questions; i++)
        {
            if (!SkipName(m, ref offset)) return "malformed question";
            offset += 4;
        }

        var answers = BinaryPrimitives.ReadUInt16BigEndian(m.AsSpan(6));
        var lines = new List<string>();
        var ech = 0;
        for (var i = 0; i < answers && offset + 10 <= m.Length; i++)
        {
            if (!SkipName(m, ref offset)) break;
            var type = BinaryPrimitives.ReadUInt16BigEndian(m.AsSpan(offset));
            var rdLength = BinaryPrimitives.ReadUInt16BigEndian(m.AsSpan(offset + 8));
            var rdata = offset + 10;
            if (rdata + rdLength > m.Length) { lines.Add("(rdata runs past the message)"); break; }
            if (type is 64 or 65) lines.Add(ServiceParams(m, rdata, rdLength, ref ech));
            else if (type is 1 or 28)
                lines.Add($"type={type} {Address(m, rdata, rdLength, type)}");
            else if (type == 5)
            {
                var after = 0;
                lines.Add($"type=5 {ReadName(m, rdata, ref after)}");
            }
            else lines.Add($"type={type} rdlen={rdLength}");
            offset = rdata + rdLength;
        }

        var head = $"rcode={flags & 0x0F}{(truncated ? " TC" : "")} an={answers} {ms} ms" +
                   (ech > 0 ? "   <<< ECH PARAMETER PRESENT >>>" : "");
        return lines.Count == 0 ? head : head + "\n  " + string.Join("\n  ", lines);
    }

    private static string Address(byte[] m, int rdata, int rdLength, ushort type) =>
        type == 1 && rdLength == 4
            ? $"{m[rdata]}.{m[rdata + 1]}.{m[rdata + 2]}.{m[rdata + 3]}"
            : type == 28 && rdLength == 16
                ? string.Join(":", Enumerable.Range(0, 8)
                    .Select(i => BinaryPrimitives.ReadUInt16BigEndian(m.AsSpan(rdata + i * 2)).ToString("x")))
                : $"rdlen={rdLength}";

    // RFC 9460 §2.2: a two-octet priority, the TargetName, then the SvcParams as key/value pairs.
    private static string ServiceParams(byte[] m, int rdata, int rdLength, ref int ech)
    {
        var priority = BinaryPrimitives.ReadUInt16BigEndian(m.AsSpan(rdata));
        var offset = rdata + 2;
        var target = ReadName(m, offset, ref offset);
        var parts = new List<string>();
        while (offset + 4 <= rdata + rdLength)
        {
            var key = BinaryPrimitives.ReadUInt16BigEndian(m.AsSpan(offset));
            var length = BinaryPrimitives.ReadUInt16BigEndian(m.AsSpan(offset + 2));
            if (offset + 4 + length > rdata + rdLength) { parts.Add("(param runs past rdata)"); break; }
            parts.Add($"{KeyName(key)}({key}) len={length}");
            if (key == 5) ech++;
            offset += 4 + length;
        }
        return $"HTTPS prio={priority} target=\"{target}\" [{string.Join(" ", parts)}]";
    }

    private static string KeyName(ushort key) => key switch
    {
        0 => "mandatory", 1 => "alpn", 2 => "no-default-alpn", 3 => "port", 4 => "ipv4hint",
        5 => "ech", 6 => "ipv6hint", _ => "other"
    };

    // RFC 1035 §4.1.4: a pointer leads back into the message, but the record's own fields continue
    // immediately after the two octets of the pointer - so the offset that comes back is where the
    // pointer ended, not where the pointed-to name ended. Reading it at the target is how this probe
    // first reported a HTTPS record with no parameters at all.
    private static bool SkipName(byte[] m, ref int offset)
    {
        var hops = 0;
        var resume = -1;
        while (offset < m.Length)
        {
            var length = m[offset];
            if (length == 0)
            {
                offset = resume >= 0 ? resume : offset + 1;
                return true;
            }
            if ((length & 0xC0) != 0)
            {
                if (offset + 2 > m.Length || ++hops > 32) return false;
                if (resume < 0) resume = offset + 2;
                offset = (length & 0x3F) << 8 | m[offset + 1];
                continue;
            }
            offset += 1 + length;
        }
        return false;
    }

    private static string ReadName(byte[] m, int start, ref int afterOffset)
    {
        var labels = new List<string>();
        var offset = start;
        var recording = true;
        var hops = 0;
        while (offset < m.Length)
        {
            var length = m[offset];
            if (length == 0)
            {
                offset++;
                if (recording) afterOffset = offset;
                break;
            }
            if ((length & 0xC0) != 0)
            {
                if (++hops > 32) break;
                if (recording) afterOffset = offset + 2;
                recording = false;
                offset = (length & 0x3F) << 8 | m[offset + 1];
                continue;
            }
            offset++;
            if (offset + length > m.Length) break;
            if (recording) labels.Add(Encoding.ASCII.GetString(m, offset, length));
            offset += length;
        }
        return string.Join(".", labels);
    }

    private static byte[] Build(string name)
    {
        var body = new List<byte>();
        foreach (var label in name.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            body.Add((byte)label.Length);
            body.AddRange(Encoding.ASCII.GetBytes(label));
        }
        body.Add(0);
        body.Add(0); body.Add(65);   // QTYPE = HTTPS
        body.Add(0); body.Add(1);    // CLASS = IN

        // An OPT record asks the resolver for a larger answer than RFC 1035 §4.2.1's 512-octet UDP limit;
        // without it a HTTPS record with several parameters is exactly the kind that comes back with TC
        // set. OPT is name 0, type 41, the class field carrying the requested UDP payload size, four
        // extended-rcode octets, and a zero RDLENGTH.
        var opt = new List<byte> { 0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0 };

        var message = new List<byte>
        {
            0x12, 0x34,             // id
            0x01, 0x00,             // RD
            0x00, 0x01,             // QDCOUNT
            0x00, 0x00,             // ANCOUNT
            0x00, 0x00,             // NSCOUNT
            0x00, 0x01,             // ARCOUNT: the OPT record
        };
        message.AddRange(body);
        message.AddRange(opt);
        return message.ToArray();
    }
}
