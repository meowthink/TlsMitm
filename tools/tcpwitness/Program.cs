using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;

// Unelevated witness for the relay's inbound probe: prints every row of the IPv4 connection table that is
// half-open or touches the port argument, once a second, for the given number of seconds. It reads the same
// table TlsMitm judges itself against, so a verdict can be checked from outside the elevated process.
//
// usage: tcpwitness [seconds] [port]      defaults: 30 seconds, the relay's own 8443
[DllImport("iphlpapi.dll", SetLastError = true)]
static extern uint GetTcpTable(nint tcpTable, ref uint sizePointer, bool order);

var seconds = args.Length > 0 ? int.Parse(args[0]) : 30;
var port = args.Length > 1 ? int.Parse(args[1]) : 8443;

for (var tick = 0; tick < seconds; tick++)
{
    uint size = 0;
    GetTcpTable(0, ref size, false);
    if (size < 4)
    {
        Console.WriteLine($"{DateTime.Now:HH:mm:ss} table size {size}");
        continue;
    }
    var buffer = Marshal.AllocHGlobal((int)size);
    try
    {
        if (GetTcpTable(buffer, ref size, false) != 0)
        {
            Console.WriteLine($"{DateTime.Now:HH:mm:ss} GetTcpTable failed");
            continue;
        }
        var raw = new byte[size];
        Marshal.Copy(buffer, raw, 0, (int)size);
        Span<byte> whole = raw;
        var rows = BinaryPrimitives.ReadUInt32LittleEndian(whole.Slice(0, 4));
        var hits = 0;
        for (var i = 0; i < rows; i++)
        {
            var fields = whole.Slice(4 + i * 20, 20);
            var state = BinaryPrimitives.ReadUInt32LittleEndian(fields);
            var localPort = BinaryPrimitives.ReadUInt16BigEndian(fields.Slice(8, 2));
            var remotePort = BinaryPrimitives.ReadUInt16BigEndian(fields.Slice(16, 2));
            if (state != 4 && localPort != port && remotePort != port) continue;
            hits++;
            Console.WriteLine($"{DateTime.Now:HH:mm:ss} state={state} " +
                              $"{new IPAddress(fields.Slice(4, 4))}:{localPort} -> " +
                              $"{new IPAddress(fields.Slice(12, 4))}:{remotePort}");
        }
        Console.WriteLine($"{DateTime.Now:HH:mm:ss} rows={rows} hits={hits}");
    }
    finally
    {
        Marshal.FreeHGlobal(buffer);
    }

    Thread.Sleep(1000);
}
