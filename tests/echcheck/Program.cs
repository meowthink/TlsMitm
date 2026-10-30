// The EchDowngrade state machine on its own: no sockets, no proxy, no certificate. The only window is
// the 10-minute blind fallback, so the clock is injected and this file advances it instead of waiting.
using TlsMitm;

var failures = new List<string>();
// TickCount64 is time since boot, so a probe timestamp of 0 means "never" in the state machine; an
// origin that large keeps the virtual clock out of that collision.
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

// 3. Silence is not failure. A GREASE-ECH session (RFC 9849 §6.2.1) finishes the terminated handshake
//    and then sits idle, which is what a browser's speculative connections to a host with no published
//    configuration do, so no amount of quiet can move the host off termination.
Advance(5_200);
Check("idle session does not blind", d.Terminate(100, "a.test", true), true);
Advance(30 * 60_000);
Check("idle session still does not blind", d.Terminate(100, "a.test", true), true);

// 4. A failed client leg is the §6.1.7 refusal: the next ECH hello goes blind, and the window is
//    sticky for the host.
d.ProbeFailed(100, "a.test");
Check("failed leg blinds the host", d.Terminate(100, "a.test", true), false);
Check("blind is sticky", d.Terminate(100, "a.test", true), false);
Check("plaintext during blind is a normal MITM", d.Terminate(100, "a.test", false), false);

// 5. A late outcome from the session that caused the blind must not extend the window: nothing is
//    terminated while a host is blind, so it cannot be new evidence.
Advance(60_000);
d.ProbeFailed(100, "a.test");
Advance(9 * 60_000 + 1);
Check("window expires on the first failure", d.Terminate(100, "a.test", true), true);

// 6. Another process and another host are independent.
Check("other pid probes independently", d.Terminate(200, "a.test", true), true);
Check("other host probes independently", d.Terminate(100, "b.test", true), true);

// 7. A plaintext hello after a failure means the client dropped ECH: nothing to terminate, and the
//    failure is forgotten rather than blinding a host that no longer sends ECH.
var r = new EchDowngrade(() => clock);
Check("first ECH terminates", r.Terminate(5, "f.test", true), true);
r.ProbeFailed(5, "f.test");
Check("plaintext drops the failure", r.Terminate(5, "f.test", false), false);
Check("ECH after a dropped failure terminates again", r.Terminate(5, "f.test", true), true);

// 8. Application bytes are the measured success signal (Edge 155 kept the connection), and they
//    outrank a sibling connection's failure: a host that has carried data keeps terminating.
var w = new EchDowngrade(() => clock);
Check("data-path probe", w.Terminate(9, "d.test", true), true);
w.ObservedData(9, "d.test");
w.ProbeFailed(9, "d.test");
Check("proven host keeps terminating after a sibling failure", w.Terminate(9, "d.test", true), true);

// 9. The proof expires, and then a failure convicts the host.
Advance(10 * 60_000 + 1);
w.ProbeFailed(9, "d.test");
Check("proof expired, failure blinds", w.Terminate(9, "d.test", true), false);

// 10. Data that arrives after a sibling failure reopens termination: it is proof from the same client,
//     and it clears the failure flag.
var q = new EchDowngrade(() => clock);
q.Terminate(3, "g.test", true);
q.ProbeFailed(3, "g.test");
q.ObservedData(3, "g.test");
Check("data after a sibling failure terminates again", q.Terminate(3, "g.test", true), true);

// 11. Data cannot undo a blind fallback: those hosts are relayed untouched, so a terminated session of
//     theirs cannot exist, and a stray call must not reopen probing.
var z = new EchDowngrade(() => clock);
z.Terminate(11, "e.test", true);
z.ProbeFailed(11, "e.test");
Check("blind armed", z.Terminate(11, "e.test", true), false);
z.ObservedData(11, "e.test");
Check("data on a blind host does not reopen probing", z.Terminate(11, "e.test", true), false);

Console.WriteLine(failures.Count == 0 ? "[echcheck] PASS" : $"[echcheck] FAIL ({failures.Count})");
return failures.Count == 0 ? 0 : 1;
