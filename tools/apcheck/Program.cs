using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using Microsoft.Win32;

// Scratch probe, not part of the offline suite: can this host bring up a software access point through
// the documented wireless Hosted Network API, and what does that API report before anyone has configured
// one? The router's second topology - Ethernet up, Wi-Fi broadcasting - needs an AP that comes up
// *without* Internet Connection Sharing, whose own DHCP and DNS on 192.168.137.1 would answer the clients
// before this program gets the chance.
//
// Without a flag, every call here is a query. WlanHostedNetworkSetProperty, SetSecondaryKey, InitSettings,
// StartUsing and StopUsing are the state-changing half of wlanapi and none of them is imported, and the
// Wi-Fi Direct publisher is activated and read but never started. The header says
// WlanHostedNetworkQueryProperty and WlanHostedNetworkQueryStatus may be called by any user, so it runs
// unelevated and reports what that actually returns here.
//
// --wfd-start is the one branch that asks for a radio, and it is the reason that branch re-reads and
// re-states everything rather than assuming: a driver that answers "Hosted network supported: no" to the
// queries above still has the Wi-Fi Direct advertisement path, and only Start can tell you whether this
// machine's driver takes it.
//
// Offsets and enum values are taken from the installed SDK headers (wlanapi.h, wlantypes.h, windot11.h)
// rather than from documentation prose, because the header is what wlansvc's RPC boundary agrees with.

if (args.Contains("--help"))
{
    Console.WriteLine("[apcheck] usage: apcheck [--wfd-start [--ssid <name>] --key-file <path>]" +
                      " [--wfd-hold <seconds>]");
    Console.WriteLine("[apcheck]   no flags: read the hosted network and the Wi-Fi Direct advertisement,");
    Console.WriteLine("[apcheck]   advertise nothing. --wfd-start holds a beacon up until it stops itself.");
    return 0;
}

var advertise = args.Contains("--wfd-start");
var hold = Value(args, "--wfd-hold") is { } text && int.TryParse(text, out var seconds) ? seconds : 120;
var ssid = Value(args, "--ssid");
var passphrase = advertise ? ReadKeyFile(Value(args, "--key-file")) : null;
if (advertise && passphrase is null) return 2;

if (Wlan.OpenHandle(out var client, out var negotiated) != 0) return 1;
try
{
    Wlan.EnumerateInterfaces(client);
    Wlan.QueryHostedProperties(client);
    Wlan.QueryHostedStatus(client);
}
finally
{
    Wlan.CloseHandle(client);
}

if (!advertise)
{
    WifiDirect.Report();
    return 0;
}

return WifiDirect.Advertise(ssid, passphrase!, hold);

static string? Value(string[] args, string name)
{
    var index = Array.IndexOf(args, name);
    return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
}

// The passphrase comes from a file and never from the command line, which would put it in the process list
// and the shell's history. Newlines are trimmed because a file edited by hand ends with one; spaces are
// kept, because the standard allows them inside a passphrase.
static string? ReadKeyFile(string? path)
{
    if (path is null)
    {
        Console.WriteLine("[apcheck] --wfd-start needs --key-file <path>: the passphrase it holds is the" +
                          " key the client joins with, and the generated default is over the WPA2-PSK ceiling");
        return null;
    }

    string passphrase;
    try
    {
        passphrase = File.ReadAllText(path).Trim('\r', '\n');
    }
    catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
    {
        Console.WriteLine($"[apcheck] cannot read --key-file {path}: {exception.Message}");
        return null;
    }

    // Checked here rather than left for the radio to judge, because the radio's answer to an unacceptable
    // passphrase is the same Aborted it gives for every other refusal. Measured on this host: a file of
    // eight NUL octets aborted, and eight printable ones advertised - same SSID, same build, minutes
    // apart. The octets outside 0x20..0x7E are ones a client cannot type into a passphrase field, so a
    // file carrying them could never be joined even if the advertisement had taken it. The 8-to-63 length
    // bound is the advertisement's own refusal, not this one's.
    for (var i = 0; i < passphrase.Length; i++)
    {
        if (passphrase[i] is >= ' ' and <= '~') continue;
        Console.WriteLine($"[apcheck] --key-file {path} holds a non-printable octet (0x{(int)passphrase[i]:x2})" +
                          $" at position {i + 1} of {passphrase.Length}; a WPA2-PSK passphrase is printable" +
                          " octets, and this host's radio answers one that is not with Aborted. The rest of" +
                          " the file is not shown.");
        return null;
    }

    return passphrase;
}

internal static class Wlan
{
    // wlanapi.h: WLAN_API_VERSION_2_0, the version every hosted-network call was added under.
    private const uint ApiVersion = 2;

    private const int ErrorSuccess = 0;
    // The hosted-network docs promise ERROR_BAD_CONFIGURATION for a connection-settings query made before
    // an SSID exists; the number is in winerror.h, which is also what FormatMessage reads.
    private const int ErrorBadConfiguration = 1610;

    private const int InterfaceDescriptionChars = 256; // WLAN_MAX_NAME_LENGTH, from l2cmn.h
    private const int InterfaceInfoSize = 16 + InterfaceDescriptionChars * 2 + 4;
    // WLAN_HOSTED_NETWORK_STATUS: state, GUID, 6-octet BSSID, then the enum and the two ULONGs on their
    // own 4-octet boundaries. PeerList follows at 40, each entry a MAC plus a padded auth enum.
    private const int StatusPhyType = 28;
    // wlanapi.h names this ulChannelFrequency without saying which of the two it carries; measured on this
    // host's driver it holds the channel index — it read 11 while netsh showed "Channel : 11", and 11 MHz is
    // not a Wi-Fi frequency.
    private const int StatusChannel = 32;
    private const int StatusPeers = 36;
    private const int StatusPeerList = 40;
    private const int PeerEntrySize = 12;
    // WLAN_HOSTED_NETWORK_CONNECTION_SETTINGS: DOT11_SSID is a ULONG length plus a 32-octet fixed array.
    private const int SsidLength = 0;
    private const int SsidBytes = 4;
    private const int MaxPeers = 36;

    private const int OpCodeConnectionSettings = 0;
    private const int OpCodeSecuritySettings = 1;
    private const int OpCodeEnable = 3;
    // WLAN_INTF_OPCODE, counted off wlanapi.h where wlan_intf_opcode_autoconf_start is 0 and every member
    // after it takes the next value.
    private const int OpCodeInterfaceState = 6;
    private const int OpCodeHostedNetworkCapable = 15;

    public static int OpenHandle(out IntPtr client, out uint negotiated)
    {
        var status = WlanOpenHandle(ApiVersion, IntPtr.Zero, out negotiated, out client);
        Console.WriteLine($"[apcheck] WlanOpenHandle {Error(status)}, negotiated API version {negotiated}");
        if (status != ErrorSuccess) client = IntPtr.Zero;
        return status;
    }

    public static void CloseHandle(IntPtr client) => Console.WriteLine(
        $"[apcheck] WlanCloseHandle {Error(WlanCloseHandle(client, IntPtr.Zero))}");

    /// The physical wireless interfaces wlansvc knows about. The hosted network's own virtual device is
    /// deliberately absent from this list - see the note on its GUID in QueryHostedStatus.
    public static void EnumerateInterfaces(IntPtr client)
    {
        var status = WlanEnumInterfaces(client, IntPtr.Zero, out var list);
        Console.WriteLine($"[apcheck] WlanEnumInterfaces {Error(status)}");
        if (status != ErrorSuccess) return;

        try
        {
            var count = Marshal.ReadInt32(list);
            for (var i = 0; i < count; i++)
            {
                var item = list + 8 + i * InterfaceInfoSize;
                var guid = Marshal.PtrToStructure<Guid>(item);
                var description = Marshal.PtrToStringUni(item + 16, InterfaceDescriptionChars)?
                    .TrimEnd('\0', ' ') ?? "";
                Console.WriteLine($"[apcheck]   interface {description}");
                Console.WriteLine($"[apcheck]     guid {guid} state {InterfaceState(Marshal.ReadInt32(item + 528))}");
                Console.WriteLine($"[apcheck]     adapter name on this machine: {AdapterName(guid)}");

                // The state is read a second time through WlanQueryInterface on purpose: that is the call
                // the line after it depends on, and the two APIs agreeing about one GUID is what shows the
                // opcode numbering was counted from the header rather than guessed at.
                var echoed = ReadInterfaceInt(client, ref guid, OpCodeInterfaceState, out var echoStatus);
                Console.WriteLine($"[apcheck]     WlanQueryInterface says {Error(echoStatus)}" +
                                  (echoStatus == ErrorSuccess ? $", state {InterfaceState(echoed)}" : ""));

                var capable = ReadInterfaceInt(client, ref guid, OpCodeHostedNetworkCapable, out var capableStatus);
                Console.WriteLine($"[apcheck]     hosted network capable: " +
                                  (capableStatus == ErrorSuccess ? (capable != 0 ? "yes" : "no") : Error(capableStatus)));
            }
        }
        finally
        {
            WlanFreeMemory(list);
        }
    }

    private static int ReadInterfaceInt(IntPtr client, ref Guid guid, int opCode, out int status)
    {
        status = WlanQueryInterface(client, ref guid, opCode, IntPtr.Zero, out var size, out var data, out _);
        if (status != ErrorSuccess) return 0;

        try
        {
            return size < 4 ? 0 : Marshal.ReadInt32(data);
        }
        finally
        {
            WlanFreeMemory(data);
        }
    }

    public static void QueryHostedProperties(IntPtr client)
    {
        // wlan_hosted_network_opcode_enable is what "netsh wlan show hostednetwork" prints as Mode, so
        // the two agree or one of them is lying about this machine.
        Query(client, OpCodeEnable, "enable", (data, _) =>
            Marshal.ReadInt32(data) != 0 ? "allowed" : "disallowed");

        Query(client, OpCodeSecuritySettings, "security settings", (data, size) => size < 8
            ? $"the blob is {size} bytes, shorter than the auth/cipher pair"
            : $"auth {Auth(Marshal.ReadInt32(data))}, cipher {Cipher(Marshal.ReadInt32(data + 4))}");

        // The station profile (opcode 2) is never queried: it hands back the SSID's XML with the
        // passphrase in it as cleartext, and this program's whole purpose is to read state, not to
        // reproduce a secret on the console.
        Query(client, OpCodeConnectionSettings, "connection settings", (data, size) => size < MaxPeers + 4
            ? $"the blob is {size} bytes, shorter than the SSID and the peer limit"
            : $"SSID {Ssid(data)}, max peers {Marshal.ReadInt32(data + MaxPeers)}");
    }

    public static void QueryHostedStatus(IntPtr client)
    {
        var status = WlanHostedNetworkQueryStatus(client, out var blob, IntPtr.Zero);
        Console.WriteLine($"[apcheck] WlanHostedNetworkQueryStatus {Error(status)}");
        if (status != ErrorSuccess) return;

        try
        {
            var state = Marshal.ReadInt32(blob);
            Console.WriteLine($"[apcheck]   hosted network state {HostedState(state)}");
            if (state == 0)
            {
                // wlanapi.h: when the state is unavailable "the values of the other fields in this
                // structure should not be used", so stop here rather than print whatever is in them.
                return;
            }

            var device = Marshal.PtrToStructure<Guid>(blob + 4);
            Console.WriteLine($"[apcheck]   virtual device {device} ({AdapterName(device)}), PnP {AdapterPnpInstance(device)}");
            Console.WriteLine($"[apcheck]   BSSID {Mac(blob + 20)}, phy {Phy(Marshal.ReadInt32(blob + StatusPhyType))}," +
                              $" channel {Marshal.ReadInt32(blob + StatusChannel)}");

            var peers = Marshal.ReadInt32(blob + StatusPeers);
            Console.WriteLine($"[apcheck]   {peers} peer(s)");
            for (var i = 0; i < peers; i++)
            {
                var entry = blob + StatusPeerList + i * PeerEntrySize;
                Console.WriteLine($"[apcheck]     {Mac(entry)} {PeerAuth(Marshal.ReadInt32(entry + 8))}");
            }
        }
        finally
        {
            WlanFreeMemory(blob);
        }
    }

    private static void Query(IntPtr client, int opCode, string name, Func<IntPtr, int, string> render)
    {
        var status = WlanHostedNetworkQueryProperty(client, opCode, out var size, out var data,
            out var valueType, IntPtr.Zero);
        Console.WriteLine($"[apcheck] hosted network {name}: {Error(status)}");
        if (status != ErrorSuccess) return;

        try
        {
            Console.WriteLine($"[apcheck]   {render(data, (int)size)}" +
                              $" (value set by {OpcodeValue(valueType)}, {size} bytes)");
        }
        finally
        {
            WlanFreeMemory(data);
        }
    }

    private static string Error(int status) => status switch
    {
        ErrorSuccess => "ERROR_SUCCESS",
        ErrorBadConfiguration => $"{status} ERROR_BAD_CONFIGURATION: {new Win32Exception(status).Message}",
        _ => $"{status}: {new Win32Exception(status).Message}",
    };

    private static string Ssid(IntPtr data)
    {
        // The length is a ULONG the driver could set past the 32-octet array it is describing, so the
        // copy is bounded by the array rather than by the field.
        var length = Math.Clamp(Marshal.ReadInt32(data), 0, 32);
        var bytes = new byte[length];
        Marshal.Copy(data + SsidBytes, bytes, 0, length);
        // An SSID is octets, not necessarily text; print the escapes rather than assume a codepage.
        var text = new StringBuilder();
        foreach (var b in bytes)
            text.Append(b is >= 0x20 and < 0x7F ? (char)b : $"\\x{b:x2}");
        return length == 0 ? "<empty>" : $"\"{text}\" ({length} octets)";
    }

    private const string NetworkClassKey = @"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}";

    private static string AdapterName(Guid device) => ConnectionValue(device, "Name") ?? "<no Connection key>";

    private static string AdapterPnpInstance(Guid device) => ConnectionValue(device, "PnpInstanceID") ?? "<none>";

    private static string? ConnectionValue(Guid device, string value)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"{NetworkClassKey}\{device:B}\Connection");
            return key?.GetValue(value) as string;
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or SecurityException)
        {
            // Reading the Control\Network tree is not denied to a user, but a machine policy can say
            // otherwise, and a probe that throws over a name is worse than one that says so.
            return $"<unreadable: {exception.GetType().Name}>";
        }
    }

    private static string InterfaceState(int value) => value switch
    {
        0 => "not_ready", 1 => "connected", 2 => "ad_hoc_network_formed", 3 => "disconnecting",
        4 => "disconnected", 5 => "associating", 6 => "discovering", 7 => "authenticating",
        _ => $"unknown ({value})",
    };

    private static string HostedState(int value) => value switch
    {
        0 => "unavailable", 1 => "idle", 2 => "active", _ => $"unknown ({value})",
    };

    private static string PeerAuth(int value) => value switch
    {
        0 => "invalid", 1 => "authenticated", _ => $"unknown ({value})",
    };

    private static string Phy(int value) => value switch
    {
        0 => "unknown/any", 1 => "fhss", 2 => "dsss", 3 => "irbaseband", 4 => "ofdm", 5 => "hrdsss",
        6 => "erp", 7 => "ht (802.11n)", 8 => "vht (802.11ac)", 9 => "dmg (802.11ad)",
        _ => $"unknown ({value})",
    };

    private static string Auth(int value) => value switch
    {
        0 => "unspecified", 1 => "802_11_open", 2 => "802_11_shared_key", 3 => "wpa", 4 => "wpa_psk",
        5 => "wpa_none", 6 => "rsna (802.1X)", 7 => "rsna_psk (WPA2-PSK)", _ => $"unknown ({value})",
    };

    private static string Cipher(int value) => value switch
    {
        0x00 => "none", 0x01 => "wep40", 0x02 => "tkip", 0x04 => "ccmp", 0x05 => "wep104", 0x06 => "bip",
        0x08 => "gcmp", 0x100 => "group", 0x101 => "wep", _ => $"unknown ({value})",
    };

    private static string OpcodeValue(int value) => value switch
    {
        0 => "query only", 1 => "group policy", 2 => "the user", 3 => "an invalid type",
        _ => $"unknown ({value})",
    };

    private static string Mac(IntPtr data)
    {
        var bytes = new byte[6];
        Marshal.Copy(data, bytes, 0, 6);
        return string.Join(':', bytes.Select(b => b.ToString("x2")));
    }

    [DllImport("wlanapi.dll")]
    private static extern int WlanOpenHandle(uint clientVersion, IntPtr reserved,
        out uint negotiatedVersion, out IntPtr clientHandle);

    [DllImport("wlanapi.dll")]
    private static extern int WlanCloseHandle(IntPtr clientHandle, IntPtr reserved);

    [DllImport("wlanapi.dll")]
    private static extern int WlanEnumInterfaces(IntPtr clientHandle, IntPtr reserved, out IntPtr interfaceList);

    [DllImport("wlanapi.dll")]
    private static extern int WlanQueryInterface(IntPtr clientHandle, ref Guid interfaceGuid, int opCode,
        IntPtr reserved, out uint dataSize, out IntPtr data, out int opcodeValueType);

    [DllImport("wlanapi.dll")]
    private static extern int WlanHostedNetworkQueryProperty(IntPtr clientHandle, int opCode,
        out uint dataSize, out IntPtr data, out int opcodeValueType, IntPtr reserved);

    [DllImport("wlanapi.dll")]
    private static extern int WlanHostedNetworkQueryStatus(IntPtr clientHandle, out IntPtr status, IntPtr reserved);

    [DllImport("wlanapi.dll")]
    private static extern void WlanFreeMemory(IntPtr memory);
}
