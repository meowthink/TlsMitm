using System.Net;

namespace TlsMitm;

/// <summary>
/// The one inbound-allow rule this program owns, reached through the firewall's COM API.
///
/// It is used for exactly two things: putting a rule with our own name in, and taking it out again. It
/// is not asked whether the relay port is reachable, because that question is not answerable here. The
/// rules that grant a service's port are pre-defined ones whose port condition lives in the filter
/// rather than in the rule, so their own port field reads as a wildcard - measured on this host, 29
/// enabled inbound allow rules carry LocalPorts='*' and would all claim to cover 8443. And the
/// documented precedence puts any explicit block rule above every allow rule regardless of how much
/// narrower the allow is ("Windows Firewall with Advanced Security: Rule precedence for inbound and
/// outbound rules"), which is what a store read cannot see coming. The verdict comes from a probe packet
/// instead - TlsMitm's RelayProbe for the relay port, Router's LanProbe for the LAN listeners - and each
/// asks the stack rather than asking the policy what it says.
/// </summary>
public static class InboundFirewall
{
    public const int ProtoTcp = 6;
    public const int ProtoUdp = 17;

    private const int DirIn = 1;
    // Measured 2026-10-31 against the live store rather than taken from the enum's declaration: the four
    // inbound router.exe rules that Get-NetFirewallRule reports as Allow each read Action=1 here. A rule
    // set to profiles 'Any' reads back as 0x7FFFFFFF, which is what ProfileAll is for.
    private const int ActionBlock = 0;
    private const int ActionAllow = 1;
    private const int ProfileAll = 0x7FFFFFFF;

    /// The policy object, or null with the reason printed. Every caller treats a null as "cannot say",
    /// never as "blocked" - a firewall this program cannot read is not a reason to stop a run.
    private static dynamic? Policy()
    {
        try
        {
            var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            if (type == null)
            {
                Console.WriteLine("[Firewall] HNetCfg.FwPolicy2 is not registered here; the firewall cannot be read");
                return null;
            }
            return Activator.CreateInstance(type);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Firewall] FwPolicy2 unavailable: {ex.GetType().Name}: {ex.Message}");
            return null;
        }
    }

    private sealed record Row(string Name, bool Enabled, int Protocol, string LocalPorts,
                              int Action, int Direction, int Profiles);

    private static List<Row> Rows(dynamic policy)
    {
        var found = new List<Row>();
        foreach (dynamic rule in policy.Rules)
        {
            found.Add(new Row(
                rule.Name?.ToString() ?? "",
                Convert.ToBoolean(rule.Enabled),
                Convert.ToInt32(rule.Protocol),
                rule.LocalPorts?.ToString() ?? "",
                Convert.ToInt32(rule.Action),
                Convert.ToInt32(rule.Direction),
                Convert.ToInt32(rule.Profiles)));
        }
        return found;
    }

    public static bool Exists(string name)
    {
        var policy = Policy();
        if (policy == null) return false;
        try
        {
            foreach (Row row in Rows(policy))
                if (row.Name == name) return true;
            return false;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Firewall] rules cannot be read: {ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }

    /// Put the rule in and read it back. The re-read is the point: an add that the API accepted and the
    /// store does not show is an add that did not happen, and an opt-in flag is only honest if it checks.
    /// Elevation is what this needs; without it the store refuses and says so.
    ///
    /// The port field is text because one rule can name the two ports Router listens on; a single caller
    /// passes its own port as a string.
    public static bool Add(string name, string description, int protocol, string ports)
    {
        var policy = Policy();
        if (policy == null) return false;
        try
        {
            var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule")
                ?? throw new InvalidOperationException("HNetCfg.FWRule is not registered");
            dynamic rule = Activator.CreateInstance(ruleType)!;
            rule.Name = name;
            rule.Description = description;
            rule.Direction = DirIn;
            rule.Action = ActionAllow;
            rule.Protocol = protocol;
            rule.LocalPorts = ports;
            rule.Profiles = ProfileAll;
            rule.Enabled = true;
            // RemoteAddress is left unset on purpose: what is being allowed is a port, and the source is
            // not something either program can name - for the relay it is whatever server a redirected
            // client asked for, and for the LAN listeners it is an address the client takes for itself.
            policy.Rules.Add(rule);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Firewall] add of '{name}' failed: {ex.GetType().Name}: {ex.Message}");
            return false;
        }

        if (!Exists(name))
        {
            Console.WriteLine($"[Firewall] '{name}' was added and is not in the store when read back; not claiming it");
            return false;
        }
        return true;
    }

    public static bool Remove(string name)
    {
        var policy = Policy();
        if (policy == null) return false;
        try
        {
            policy.Rules.Remove(name);
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Firewall] remove of '{name}' failed: {ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }

    /// The inbound block rules that could outrank an allow on this port, which is the only reading of a
    /// failure that a store can give. A wildcard port counts as covering it, because that is what
    /// pre-defined rules report; the list is offered as candidates, not as the verdict.
    public static IReadOnlyList<string> BlockCandidates(int protocol, int port)
    {
        var policy = Policy();
        if (policy == null) return Array.Empty<string>();
        try
        {
            var active = Convert.ToInt32(policy.CurrentProfileTypes);
            var names = new List<string>();
            foreach (Row row in Rows(policy))
            {
                if (!row.Enabled || row.Direction != DirIn || row.Action != ActionBlock) continue;
                if (row.Protocol != protocol && row.Protocol != 256) continue;
                if ((row.Profiles & active) == 0 && row.Profiles != ProfileAll) continue;
                if (!CoversPort(row.LocalPorts, port)) continue;
                names.Add(row.Name);
            }
            return names;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Firewall] block rules cannot be read: {ex.GetType().Name}: {ex.Message}");
            return Array.Empty<string>();
        }
    }

    public static string EnabledState()
    {
        var policy = Policy();
        if (policy == null) return "unknown";
        try
        {
            var active = Convert.ToInt32(policy.CurrentProfileTypes);
            var parts = new List<string>();
            foreach (var (bit, label) in new[] { (1, "Domain"), (2, "Private"), (4, "Public") })
                if ((active & bit) != 0)
                    parts.Add($"{label}={Convert.ToBoolean(policy.FirewallEnabled(bit))}");
            return string.Join(" ", parts);
        }
        catch
        {
            return "unknown";
        }
    }

    /// Whether a rule's port field names this port. Wildcards and ranges count, because a pre-defined
    /// rule's field is a wildcard even where its filter is not - so a match here is only ever a
    /// candidate, never a permission.
    public static bool CoversPort(string localPorts, int port)
    {
        if (string.IsNullOrWhiteSpace(localPorts)) return false;
        foreach (var raw in localPorts.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var token = raw.Trim();
            if (token is "*" or "?" ||
                token.Equals("any", StringComparison.OrdinalIgnoreCase) ||
                token.Equals("default", StringComparison.OrdinalIgnoreCase))
                return true;
            var dash = token.IndexOf('-');
            if (dash > 0 && int.TryParse(token[..dash], out var low) && int.TryParse(token[(dash + 1)..], out var high))
            {
                if (low <= port && port <= high) return true;
            }
            else if (int.TryParse(token, out var one) && one == port) return true;
        }
        return false;
    }
}
