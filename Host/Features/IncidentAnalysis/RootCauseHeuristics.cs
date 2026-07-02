
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

            if (site.Snat.Suspected && site.Snat.TotalSuspectFailures > 0)
            {
                var top = site.Snat.ByTarget.FirstOrDefault();
                if (top is not null)
                {
                    causes.Add($"SNAT-suspected: {site.Snat.TotalSuspectFailures} outbound timeouts (peak target: {top.Target}, {top.Failures} failures) during window.");
                }
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
