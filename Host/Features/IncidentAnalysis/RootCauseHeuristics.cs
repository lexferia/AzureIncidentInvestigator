
namespace AzureIncidentInvestigator;

public static class RootCauseHeuristics
{
    public static IReadOnlyList<string> Derive(
        Incident incident,
        AppServicePlanHealth? plan,
        AppServiceSiteHealth? site,
        IReadOnlyList<DatabaseHealth> dbs,
        IReadOnlyList<DetectorResult>? detectors = null)
    {
        var causes = new List<string>();
        var downStart = incident.DownStartUtc;

        // Detector evidence is platform-authoritative — surface it first.
        if (detectors is not null)
        {
            foreach (var d in detectors.Where(d => d.Status is DetectorStatus.Critical or DetectorStatus.Warning))
            {
                var severity = d.Status == DetectorStatus.Critical ? "CRITICAL" : "warning";
                var summary = string.IsNullOrWhiteSpace(d.StatusMessage.Value)
                    ? d.Insights.FirstOrDefault()?.Title.Value ?? ""
                    : d.StatusMessage.Value;
                causes.Add($"App Service detector `{d.Kind}` reports {severity}: {summary}");
            }
        }

        if (site is not null)
        {
            foreach (var restart in site.Restarts.OrderBy(r => r.AtUtc))
            {
                var delta = downStart - restart.AtUtc;
                if (Math.Abs(delta.TotalMinutes) <= 5)
                {
                    causes.Add($"App restarted at {restart.AtUtc:u} ({restart.OperationName}), {(delta.TotalSeconds >= 0 ? "before" : "during")} downtime by {Math.Abs(delta.TotalSeconds):F0}s — likely cause.");
                }
            }

            // Authoritative SNAT verdict from the platform detector — never inferred from dependency failures.
            if (site.Snat.Verdict is SnatVerdict.Exhausted or SnatVerdict.Suspected)
            {
                var label = site.Snat.Verdict == SnatVerdict.Exhausted ? "SNAT port exhaustion CONFIRMED" : "SNAT port exhaustion SUSPECTED";
                var detail = site.Snat.Evidence.Count > 0 ? site.Snat.Evidence[0].Value : "";
                causes.Add($"{label} by the App Service SNAT Port Exhaustion detector{(string.IsNullOrWhiteSpace(detail) ? "" : $": {detail}")}.");
            }

            // Outbound dependency failures are an application-level signal, reported separately and
            // explicitly NOT presented as SNAT exhaustion.
            var deps = site.OutboundDependencyFailures;
            if (deps.TotalFailures > 0)
            {
                var top = deps.ByTarget.FirstOrDefault();
                var target = top is not null ? $" (top target: {top.Target}, {top.Failures} failures)" : "";
                causes.Add($"{deps.TotalFailures} outbound dependency failures during window{target} — application-level (slow/erroring backend or client timeouts), not SNAT.");
            }
        }

        if (plan is not null)
        {
            if (plan.Verdict == Verdict.Saturated || plan.Cpu.Max >= 90)
            {
                causes.Add($"App Service Plan CPU saturated: avg {plan.Cpu.Avg:F0}%, p95 {plan.Cpu.P95:F0}%, max {plan.Cpu.Max:F0}% (over {plan.Cpu.MinutesOverThreshold} min).");
            }
            if (plan.Memory.Max >= 90)
            {
                causes.Add($"Memory pressure: avg {plan.Memory.Avg:F0}%, max {plan.Memory.Max:F0}%.");
            }
            if (plan.InstanceCount.ScaleEvents.Any(e => e.Direction == ScaleDirection.Down))
            {
                var sd = plan.InstanceCount.ScaleEvents.First(e => e.Direction == ScaleDirection.Down);
                causes.Add($"Plan downscaled {sd.FromCount}→{sd.ToCount} at {sd.AtUtc:u} during the incident window.");
            }
        }

        foreach (var db in dbs)
        {
            if (db.Verdict == Verdict.Saturated)
            {
                causes.Add($"Database `{db.Key}` ({db.Type}) saturated: CPU avg {db.Cpu.Avg:F0}%, max {db.Cpu.Max:F0}%.");
            }
            else if (db.Verdict == Verdict.Degraded)
            {
                causes.Add($"Database `{db.Key}` degraded: CPU avg {db.Cpu.Avg:F0}%.");
            }
        }

        if (causes.Count == 0)
        {
            causes.Add("No infrastructure-level root cause heuristics fired. Review exceptions and dependencies in the report for application-level causes.");
        }

        return causes;
    }
}
