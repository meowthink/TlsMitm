// The EchDowngrade state machine on its own: no sockets, no proxy, no certificate. The windows it
// decides on are 5s and 10min, so the clock is injected and this file advances it instead of waiting.
using TlsMitm;

var failures = new List<string>();
// TickCount64 is time since boot, so a probe timestamp of 0 means "never probed" in the state
// machine; an origin that large keeps the virtual clock out of that collision.
var clock = 1_000_000L;
void Advance(int ms) => clock += ms;
var d = new EchDowngrade(() => clock);

void Check(string name, bool actual, bool expected)
{
    Console.WriteLine($"  {(actual == expected ? "ok" : "FAIL")} {name}: {actual}");
    if (actual != expected) failures.Add(name);
}

// 1. First ECH hello: probe.
Check("first ECH terminates", d.Terminate(100, "a.test", true), true);

// 2. The plaintext retry is what proves it worked.
Check("plaintext retry does not terminate", d.Terminate(100, "a.test", false), false);

// 3. After a proven downgrade, a later ECH hello probes again (the client's disable can expire).
Check("ECH after success probes again", d.Terminate(100, "a.test", true), true);

// 4. Window expires: the second ECH marks the host blind, so the site keeps loading.
Advance(5_200);
Check("late ECH falls back to blind", d.Terminate(100, "a.test", true), false);

// 5. The fallback is sticky for the host.
Check("subsequent ECH stays blind", d.Terminate(100, "a.test", true), false);

// 6. Another process and another host are independent.
Check("other pid probes independently", d.Terminate(200, "a.test", true), true);
Check("other host probes independently", d.Terminate(100, "b.test", true), true);

// 7. A plaintext connection while blind is just a normal MITM session.
Check("plaintext during blind is not a probe", d.Terminate(100, "a.test", false), false);

// 8. Parallel ECH hellos inside the window are all terminated, and they do not extend it: the
//    earliest probe decides, so the fallback still lands 5s after the first hello.
var p = new EchDowngrade(() => clock);
Check("probe at t0", p.Terminate(7, "c.test", true), true);
Advance(1_500);
Check("parallel ECH at t1.5 terminates", p.Terminate(7, "c.test", true), true);
Advance(4_000);
Check("t5.5 is past the first window - blind", p.Terminate(7, "c.test", true), false);

// 9. Application bytes on the terminated session are the measured success signal (Edge 155 kept the
//    connection), so they prove the host: a later ECH hello is still terminated, never blind, even
//    past the 5s window.
var w = new EchDowngrade(() => clock);
Check("data-path probe", w.Terminate(9, "d.test", true), true);
w.ObservedData(9, "d.test");
Advance(5_200);
Check("proven host still terminates past the build window", w.Terminate(9, "d.test", true), true);
Check("proven host keeps terminating", w.Terminate(9, "d.test", true), true);
Check("plaintext on a proven host is a normal MITM", w.Terminate(9, "d.test", false), false);

// 10. Data cannot undo a blind fallback: those hosts are relayed untouched, so a terminated session
//     of theirs cannot exist, and a stray call must not reopen probing.
var z = new EchDowngrade(() => clock);
z.Terminate(11, "e.test", true);
Advance(5_200);
Check("blind armed", z.Terminate(11, "e.test", true), false);
z.ObservedData(11, "e.test");
Check("data on a blind host does not reopen probing", z.Terminate(11, "e.test", true), false);

Console.WriteLine(failures.Count == 0 ? "[echcheck] PASS" : $"[echcheck] FAIL ({failures.Count})");
return failures.Count == 0 ? 0 : 1;
