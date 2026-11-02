using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

// The path Microsoft hands the software access point to once a driver stops serving the hosted network:
// "Developers of desktop applications can use this sample to see how to replace the deprecated
// WlanHostedNetwork* API's with the new WinRT API's without modifying the application to become a
// Universal Windows Application", and WiFiDirectLegacySettings.IsEnabled is documented as a mode that
// "causes this device to act as a normal Wi-Fi access point, and is intended to support devices which do
// not support connection via Wi-Fi Direct". That is the shape this project wants: a phone joins an SSID
// with a passphrase, and the phone needs no Wi-Fi Direct stack of its own.
//
// Nothing here is projected by the runtime, so the interfaces are declared by hand. The GUIDs and the slot
// order come from the installed SDK's winrt/windows.devices.wifidirect.idl and
// winrt/windows.security.credentials.idl; the three IInspectable slots that precede the declared ones come
// from winrt/inspectable.h (GetIids, GetRuntimeClassName, GetTrustLevel, in that order); the WinRT
// `boolean` is the one-octet `typedef unsigned char boolean` of shared/rpcndr.h, which is why every boolean
// slot below is a byte. An HSTRING is an opaque handle rather than a wide string, so its slots stay IntPtr
// and only the helpers at the bottom of this file cross between the two.
//
// Report() is still read-only: it activates the publisher and reads back what the advertisement and the
// legacy settings hold before anyone has asked for a radio, and never calls Start. Advertise() is the only
// state-changing half, it is reached by --wfd-start, and it stops the advertisement again on the way out.

internal static class WifiDirect
{
    private const string PublisherClass = "Windows.Devices.WiFiDirect.WiFiDirectAdvertisementPublisher";
    private const int RoInitMultithreaded = 1; // roapi.h: RO_INIT_MULTITHREADED
    private const int RpcChangedMode = unchecked((int)0x80010106); // already initialised in another mode
    private const int SsidMaxOctets = 32; // DOT11_SSID_MAX_LENGTH, the bound Wlan's own SSID blob uses too
    private const int Started = 1;
    private const int ScManagerConnect = 0x0001; // winsvc.h
    private const int ServiceQueryStatus = 0x0004;
    private const int ServiceRunning = 0x0004; // SERVICE_RUNNING, winsvc.h

    /// What the publisher reports about this machine's ability to hold the access-point role. The
    /// publisher's own status is the capability answer, because that is where the
    /// WiFiDirectError_RadioNotAvailable and WiFiDirectError_ResourceInUse cases surface.
    public static void Report()
    {
        Console.WriteLine($"[apcheck] Wi-Fi Direct: RoInitialize {Hr(RoInitialize(RoInitMultithreaded))}");
        var (publisher, advertisement, legacy) = Open();
        if (publisher is null || advertisement is null || legacy is null) return;

        Console.WriteLine($"[apcheck]   publisher activated, status {StatusName(publisher.Status)}");
        Console.WriteLine($"[apcheck]   advertisement: autonomous group owner" +
                          $" {(advertisement.IsAutonomousGroupOwnerEnabled != 0 ? "enabled" : "off")}," +
                          $" legacy mode {(legacy.IsEnabled != 0 ? "enabled" : "off")}, SSID \"{Ssid(legacy)}\"");
        // The Passphrase slot is only ever read by the client that is about to write it. It holds a network
        // key, and this program already refuses to print the hosted network's station profile for that
        // reason, so nothing here asks it for one.
        Console.WriteLine("[apcheck]   nothing advertised: Start is only called by --wfd-start");
    }

    /// Advertise, hold the beacon up for `holdSeconds`, then stop. Returns the exit code.
    public static int Advertise(string? ssid, string passphrase, int holdSeconds)
    {
        // Measured on this host: a hosted network left on its system-generated 64-character key beacons a
        // passphrase no client can type, because WPA2-PSK takes a passphrase of 8 to 63 octets and the
        // clients simply never associate. Enforcing the bound here keeps that from reading again as a radio
        // or a router fault.
        var keyOctets = Encoding.UTF8.GetByteCount(passphrase);
        if (keyOctets is < 8 or > 63)
        {
            Console.WriteLine($"[apcheck] refusing to advertise: the passphrase is {keyOctets} octets and" +
                              " WPA2-PSK takes 8 to 63; point --key-file at one inside that range");
            return 2;
        }

        if (ssid is not null && Encoding.UTF8.GetByteCount(ssid) is 0 or > SsidMaxOctets)
        {
            Console.WriteLine($"[apcheck] refusing to advertise: the SSID must be 1 to {SsidMaxOctets} octets");
            return 2;
        }

        // "The Mobile Hotspot and Wi-Fi Direct technologies cannot run at the same time. Mobile Hotspot
        // takes precedence over all Wi-Fi Direct scenarios", and a hotspot started after this call leaves it
        // "likely to stop working". Refusing up front is the only honest reading of that.
        if (ServiceState("icssvc") == ServiceRunning)
        {
            Console.WriteLine("[apcheck] refusing to advertise: the Mobile Hotspot service (icssvc) is running and" +
                              " takes precedence over Wi-Fi Direct; stop it first");
            return 2;
        }

        var before = ListAdapters("before Start");
        var (publisher, advertisement, legacy) = Open();
        if (publisher is null || advertisement is null || legacy is null) return 3;

        // "Must set the autonomous group owner (GO) enabled flag - Legacy Wi-Fi Direct advertisement uses a
        // Wi-Fi Direct GO to act as an access point to legacy settings", and the line below is the companion
        // half of the same note: without it the advertisement is Wi-Fi Direct only, and a plain client has
        // nothing to join.
        advertisement.IsAutonomousGroupOwnerEnabled = 1;
        legacy.IsEnabled = 1;
        if (ssid is null) ssid = Ssid(legacy); // keep the DIRECT-xxxx value the settings already carry
        else SetSsid(legacy, ssid);

        // The credential object the settings hand back is the one the advertisement authenticates with, so
        // the passphrase is written into it rather than replaced.
        SetPassword(legacy, passphrase);

        Console.WriteLine($"[apcheck] advertising \"{ssid}\" ({Encoding.UTF8.GetByteCount(ssid)} SSID octets," +
                          $" {keyOctets} passphrase octets, not shown)");
        try
        {
            publisher.Start();
        }
        catch (Exception exception)
        {
            Console.WriteLine($"[apcheck]   Start failed: {exception.GetType().Name}: {exception.Message}");
            StopQuietly(publisher);
            ListAdapters("after the failed Start", before);
            return 3;
        }

        var status = 0;
        var deadline = Environment.TickCount64 + 10_000;
        do
        {
            status = publisher.Status;
            if (status != 0) break;
            Thread.Sleep(100);
        }
        while (Environment.TickCount64 < deadline);

        Console.WriteLine($"[apcheck]   publisher status {StatusName(status)}");
        if (status != Started)
        {
            if (status == 0)
            {
                // A Start the radio has not answered can still be answered later, so this path stops rather
                // than leave a beacon to come up behind an exited process.
                StopQuietly(publisher);
                Console.WriteLine("[apcheck]   nothing within 10s: the radio never answered the request");
            }
            else
            {
                // Measured here: Stop() on a publisher the radio already refused answers E_UNEXPECTED
                // (0x8000000E), so it is only owed to one that is still Created.
                Console.WriteLine("[apcheck]   not stopping: the publisher has already given up, and " +
                                  $"its status is {StatusName(status)}");
            }

            Diagnose("at the failed Start");
            ListAdapters("after the failed Start", before);
            return 3;
        }

        // The virtual adapter's ifIndex is what the router's --lan has to name, and a Wi-Fi Direct
        // advertisement has no wlanapi status to read, so the interface list is the evidence.
        var after = ListAdapters("after Start", before);

        var stopRequested = false;
        void OnCancel(object? sender, ConsoleCancelEventArgs e)
        {
            e.Cancel = true; // let the finally below run, so the beacon does not outlive the terminal
            stopRequested = true;
        }

        Console.CancelKeyPress += OnCancel;
        try
        {
            Console.WriteLine($"[apcheck]   join \"{ssid}\" from the client now, holding {holdSeconds}s" +
                              " (Ctrl-C stops it early)");
            var until = Environment.TickCount64 + holdSeconds * 1000L;
            while (!stopRequested && Environment.TickCount64 < until) Thread.Sleep(250);
        }
        finally
        {
            Console.CancelKeyPress -= OnCancel;
            StopQuietly(publisher);
            ListAdapters("after Stop", after);
        }

        return 0;
    }

    private static (IWiFiDirectAdvertisementPublisher?, IWiFiDirectAdvertisement?, IWiFiDirectLegacySettings?) Open()
    {
        var classHandle = CreateString(PublisherClass);
        try
        {
            var hr = RoActivateInstance(classHandle, out var publisher);
            if (hr != 0 || publisher is null)
            {
                Console.WriteLine($"[apcheck]   RoActivateInstance failed: {Hr(hr)}");
                return (null, null, null);
            }

            var advertisement = publisher.Advertisement;
            return (publisher, advertisement, advertisement.LegacySettings);
        }
        finally
        {
            WindowsDeleteString(classHandle);
        }
    }

    private static string Ssid(IWiFiDirectLegacySettings settings) => ReadString(settings.SsidHandle);

    private static void SetSsid(IWiFiDirectLegacySettings settings, string value)
    {
        var handle = CreateString(value);
        try
        {
            settings.SsidHandle = handle;
        }
        finally
        {
            // The setter keeps its own reference, which is the whole point of an immutable HSTRING.
            WindowsDeleteString(handle);
        }
    }

    private static void SetPassword(IWiFiDirectLegacySettings settings, string value)
    {
        var credential = settings.Passphrase;
        var handle = CreateString(value);
        try
        {
            credential.PasswordHandle = handle;
        }
        finally
        {
            WindowsDeleteString(handle);
        }
    }

    /// The way out of every --wfd-start path, including the ones where Stop itself refuses: a beacon must
    /// not outlive the process that asked for it.
    private static void StopQuietly(IWiFiDirectAdvertisementPublisher publisher)
    {
        try
        {
            publisher.Stop();
            Console.WriteLine($"[apcheck]   publisher status after Stop {StatusName(publisher.Status)}");
        }
        catch (Exception exception)
        {
            Console.WriteLine($"[apcheck]   Stop failed: {exception.GetType().Name}: {exception.Message}");
        }
    }

    /// The interface list. Reading it out of iphlpapi's adapter structures is a bigger offset risk than a
    /// process spawn, which is the same reasoning the router gives for shelling out for interface state.
    /// Returns the printed text so a caller can show what appeared and what vanished.
    private static string ListAdapters(string when, string? previous = null)
    {
        var text = Run("Get-NetAdapter | Sort-Object ifIndex | " +
                       "Format-Table ifIndex,Name,InterfaceDescription,Status,MacAddress -AutoSize | " +
                       "Out-String -Width 160");
        Console.WriteLine($"[apcheck]   adapters {when}:");
        foreach (var line in Lines(text)) Console.WriteLine($"[apcheck]     {line}");
        if (previous is not null)
        {
            var added = Lines(text).Except(Lines(previous)).ToList();
            var gone = Lines(previous).Except(Lines(text)).ToList();
            Console.WriteLine($"[apcheck]     appeared: {(added.Count == 0 ? "none" : string.Join(" | ", added))}");
            Console.WriteLine($"[apcheck]     vanished: {(gone.Count == 0 ? "none" : string.Join(" | ", gone))}");
        }

        return text;
    }

    private static IEnumerable<string> Lines(string text) =>
        text.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith('-'));

    private static string Run(string command)
    {
        try
        {
            var info = new ProcessStartInfo("powershell.exe",
                $"-NoProfile -NonInteractive -Command \"{command}\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var process = Process.Start(info)!;
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(15_000);
            return output;
        }
        catch (Exception exception)
        {
            return $"<{exception.GetType().Name}: {exception.Message}>";
        }
    }

    /// The two causes the publisher's status stands for - the radio unavailable, and the resource in use -
    /// read from what this host can actually see, because the specific error arrives only on the
    /// StatusChanged delegate, whose closed GUID this file does not declare.
    private static void Diagnose(string when)
    {
        Console.WriteLine($"[apcheck]   {when}: SharedAccess {ServiceName(ServiceState("SharedAccess"))}," +
                          $" icssvc {ServiceName(ServiceState("icssvc"))}");
        // Measured here: a legacy advertisement is served through wlansvc's own hosted-network role - the
        // successful run logged WLAN-AutoConfig 8005/8006 "begun/finished starting the hosted network" and
        // 20019/20020 "A client has associated / authenticated with the hosted network" - so a role the
        // previous run left claimed shows up in exactly this output. SSID and cipher are printed; the key
        // is not, and no path here asks for it.
        foreach (var line in Lines(Run("netsh wlan show hostednetwork")))
            if (line.Contains("Status") || line.Contains("SSID name"))
                Console.WriteLine($"[apcheck]     {line}");
    }

    private static string ServiceName(int state) => state switch
    {
        // winsvc.h SERVICE_STATUS.dwCurrentState, one through seven in declaration order.
        1 => "stopped", 2 => "start pending", 3 => "stop pending", 4 => "running",
        5 => "continue pending", 6 => "pause pending", 7 => "paused",
        -1 => "unreadable", _ => $"unknown ({state})",
    };

    private static int ServiceState(string name)
    {
        var manager = OpenSCManager(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero) return -1;
        try
        {
            var service = OpenService(manager, name, ServiceQueryStatus);
            if (service == IntPtr.Zero) return -1;
            try
            {
                return QueryServiceStatus(service, out var status) != 0 ? status.currentState : -1;
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }

    private static string StatusName(int status) => status switch
    {
        0 => "Created (not advertising)", 1 => "Started", 2 => "Stopped", 3 => "Aborted",
        _ => $"unknown ({status})",
    };

    private static string Hr(int hr) => hr switch
    {
        0 => "S_OK",
        1 => "S_FALSE",
        RpcChangedMode => "RPC_E_CHANGED_MODE (already initialised, kept)",
        _ => $"0x{hr:x8} {new Win32Exception(hr).Message}",
    };

    private static IntPtr CreateString(string value)
    {
        var hr = WindowsCreateString(value, (uint)value.Length, out var handle);
        if (hr != 0) throw new Win32Exception(hr, "WindowsCreateString failed");
        return handle;
    }

    private static string ReadString(IntPtr handle)
    {
        if (handle == IntPtr.Zero) return "";
        try
        {
            var buffer = WindowsGetStringRawBuffer(handle, out var length);
            return length == 0 ? "" : Marshal.PtrToStringUni(buffer, (int)length) ?? "";
        }
        finally
        {
            WindowsDeleteString(handle);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS
    {
        public int serviceType;
        public int currentState;
        public int controlsAccepted;
        public int win32ExitCode;
        public int serviceSpecificExitCode;
        public int checkPoint;
        public int waitHint;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManager(string? machine, string? database, int access);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenService(IntPtr handle, string name, int access);

    [DllImport("advapi32.dll")]
    private static extern int QueryServiceStatus(IntPtr handle, out SERVICE_STATUS status);

    [DllImport("advapi32.dll")]
    private static extern int CloseServiceHandle(IntPtr handle);

    [DllImport("api-ms-win-core-winrt-l1-1-0.dll")]
    private static extern int RoInitialize(int initType);

    [DllImport("api-ms-win-core-winrt-l1-1-0.dll")]
    private static extern int RoActivateInstance(IntPtr classId,
        out IWiFiDirectAdvertisementPublisher instance);

    [DllImport("api-ms-win-core-winrt-string-l1-1-0.dll")]
    private static extern int WindowsCreateString(
        [MarshalAs(UnmanagedType.LPWStr)] string source, uint length, out IntPtr stringHandle);

    [DllImport("api-ms-win-core-winrt-string-l1-1-0.dll")]
    private static extern IntPtr WindowsGetStringRawBuffer(IntPtr stringHandle, out uint length);

    [DllImport("api-ms-win-core-winrt-string-l1-1-0.dll")]
    private static extern int WindowsDeleteString(IntPtr stringHandle);

    // Every interface below is IInspectable-derived, so the header's three slots come first and the IDL's
    // declared members follow in declaration order, getters before setters.

    [ComImport, Guid("B35A2D1A-9B1F-45D9-925A-694D66DF68EF"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IWiFiDirectAdvertisementPublisher
    {
        void GetIids(out uint count, out IntPtr iids);
        void GetRuntimeClassName(out IntPtr className);
        void GetTrustLevel(out int level);

        IWiFiDirectAdvertisement Advertisement { get; }
        int Status { get; }
        void AddStatusChanged(IntPtr handler, out long token);
        void RemoveStatusChanged(long token);
        void Start();
        void Stop();
    }

    [ComImport, Guid("AB511A2D-2A06-49A1-A584-61435C7905A6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IWiFiDirectAdvertisement
    {
        void GetIids(out uint count, out IntPtr iids);
        void GetRuntimeClassName(out IntPtr className);
        void GetTrustLevel(out int level);

        IntPtr InformationElements { get; set; }
        int ListenStateDiscoverability { get; set; }
        byte IsAutonomousGroupOwnerEnabled { get; set; }
        IWiFiDirectLegacySettings LegacySettings { get; }
    }

    [ComImport, Guid("A64FDBBA-F2FD-4567-A91B-F5C2F5321057"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IWiFiDirectLegacySettings
    {
        void GetIids(out uint count, out IntPtr iids);
        void GetRuntimeClassName(out IntPtr className);
        void GetTrustLevel(out int level);

        byte IsEnabled { get; set; }
        IntPtr SsidHandle { get; set; }
        IPasswordCredential Passphrase { get; set; }
    }

    [ComImport, Guid("6AB18989-C720-41A7-A6C1-FEADB36329A0"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IPasswordCredential
    {
        void GetIids(out uint count, out IntPtr iids);
        void GetRuntimeClassName(out IntPtr className);
        void GetTrustLevel(out int level);

        IntPtr ResourceHandle { get; set; }
        IntPtr UserNameHandle { get; set; }
        IntPtr PasswordHandle { get; set; }
        void RetrievePassword();
        IntPtr Properties { get; }
    }
}
