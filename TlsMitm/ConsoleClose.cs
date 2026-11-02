using System.Runtime.InteropServices;

namespace TlsMitm;

/// The stop that no exit handler sees. Closing a console window - the X button, and also what taskkill
/// without /F asks for - delivers CTRL_CLOSE_EVENT, which measured 2026-11-02 on this host reaches neither
/// Console.CancelKeyPress nor AppDomain.ProcessExit, so the run ends with whatever it had added still in
/// place. A Win32 control handler is the one in-process thing that does receive it.
public static class ConsoleClose
{
    /// The CTRL_CLOSE_EVENT number from wincon.h. The same callback also sees the logoff (5) and shutdown
    /// (6) events; only the close was measured here, and all three end the process the same way.
    public const uint CloseEvent = 2;

    private delegate bool ConsoleCtrlDelegate(uint ctrlType);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetConsoleCtrlHandler(ConsoleCtrlDelegate handlerRoutine, bool add);

    // Rooted in a static field: the native registration holds only a function pointer, so a delegate that
    // managed code stops referencing gets collected and the callback lands on a dead thunk.
    private static ConsoleCtrlDelegate? callback;

    /// Runs release when the console is closed, on the thread the system creates for the event, and returns
    /// false so the handlers already in the chain - and the end of the process - go ahead as they would.
    /// Two measured bounds on what release may be: the system waits about 5 s and then terminates the
    /// process whatever the handler does (one that slept 6 s was killed at 4.85 s, never reaching its next
    /// line), and the firewall's COM call does work from this thread (886 rules enumerated in 120 ms), so
    /// the quick store call is in budget and anything slower is not. An exception here would only cost the
    /// remaining rules, so nothing is allowed to escape it: the process is ending regardless of what this
    /// thread says.
    public static bool Register(Action release)
    {
        callback = ctrlType =>
        {
            if (ctrlType != CloseEvent) return false;
            try
            {
                release();
            }
            catch
            {
            }
            return false;
        };
        return SetConsoleCtrlHandler(callback, true);
    }
}
