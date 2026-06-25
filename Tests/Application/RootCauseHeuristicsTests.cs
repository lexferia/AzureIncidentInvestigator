using FluentAssertions;
using AzureIncidentInvestigator.Application.Incidents;
using AzureIncidentInvestigator.Domain.Diagnostics;
using AzureIncidentInvestigator.Domain.Incidents;
using AzureIncidentInvestigator.Domain.Metrics;
using AzureIncidentInvestigator.Domain.Shared;
using Xunit;

namespace AzureIncidentInvestigator.Tests.Application;

public class RootCauseHeuristicsTests
{
    private static Incident MakeIncident(DateTimeOffset downStart) =>
        new("1:1", 1, "site", "https://site", downStart, downStart.AddMinutes(5), 300, "down");

    [Fact]
    public void Derive_AppRestartBeforeDowntime_AddsCause()
    {
        var down = DateTimeOffset.UtcNow.AddHours(-1);
        var inc = MakeIncident(down);
        var site = new AppServiceSiteHealth(
            "/r",
            new[] { new RestartEvent(down.AddSeconds(-51), "Application stopped", new SanitizedString("recycle")) },
            new SnatExhaustionFinding(false, 0, Array.Empty<SnatTargetFailure>(), null));
        var causes = RootCauseHeuristics.Derive(inc, plan: null, site: site, dbs: Array.Empty<DatabaseHealth>());
        causes.Should().Contain(c => c.Contains("restarted", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Derive_PlanSaturated_AddsCause()
    {
        var inc = MakeIncident(DateTimeOffset.UtcNow);
        var plan = new AppServicePlanHealth(
            "/r",
            new MetricSummary(92, 98, 99, 8, DateTimeOffset.UtcNow),
            new MetricSummary(50, 60, 65, 0, DateTimeOffset.UtcNow),
            new MetricSummary(0, 0, 0, 0, null),
            new MetricSummary(0, 0, 0, 0, null),
            new InstanceCountAnalysis(1, 1, Array.Empty<ScaleEvent>()),
            Verdict.Saturated);
        var causes = RootCauseHeuristics.Derive(inc, plan, site: null, dbs: Array.Empty<DatabaseHealth>());
        causes.Should().Contain(c => c.Contains("CPU", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Derive_SnatSuspected_AddsCause()
    {
        var inc = MakeIncident(DateTimeOffset.UtcNow);
        var site = new AppServiceSiteHealth(
            "/r",
            Array.Empty<RestartEvent>(),
            new SnatExhaustionFinding(true, 142,
                new[] { new SnatTargetFailure(new SanitizedString("api.partner.com"), 142, DateTimeOffset.UtcNow) },
                DateTimeOffset.UtcNow));
        var causes = RootCauseHeuristics.Derive(inc, plan: null, site, dbs: Array.Empty<DatabaseHealth>());
        causes.Should().Contain(c => c.Contains("SNAT", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Derive_DatabaseSaturated_AddsCause()
    {
        var inc = MakeIncident(DateTimeOffset.UtcNow);
        var db = new DatabaseHealth(
            "prod-app-db",
            DatabaseType.SqlDatabase,
            new MetricSummary(95, 98, 99, 10, DateTimeOffset.UtcNow),
            null, null, null,
            Verdict.Saturated);
        var causes = RootCauseHeuristics.Derive(inc, plan: null, site: null, dbs: new[] { db });
        causes.Should().Contain(c => c.Contains("prod-app-db", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Derive_DetectorCritical_AddsCauseFirst()
    {
        var inc = MakeIncident(DateTimeOffset.UtcNow);
        var detector = new DetectorResult(
            DetectorKind.SnatPortExhaustion,
            DetectorStatus.Critical,
            new SanitizedString("Outbound SNAT ports exhausted on instance RD0003FF8."),
            new[] { new DetectorInsight(new SanitizedString("SNAT spike"), new SanitizedString("142 failures"), 12) });
        var causes = RootCauseHeuristics.Derive(inc, plan: null, site: null, dbs: Array.Empty<DatabaseHealth>(), new[] { detector });
        causes.Should().NotBeEmpty();
        causes[0].Should().Contain("SnatPortExhaustion").And.Contain("CRITICAL");
    }

    [Fact]
    public void Derive_DetectorHealthy_DoesNotAddCause()
    {
        var inc = MakeIncident(DateTimeOffset.UtcNow);
        var healthy = new DetectorResult(
            DetectorKind.HighCpu, DetectorStatus.Healthy,
            new SanitizedString("All good"), Array.Empty<DetectorInsight>());
        var causes = RootCauseHeuristics.Derive(inc, plan: null, site: null, dbs: Array.Empty<DatabaseHealth>(), new[] { healthy });
        causes.Should().NotContain(c => c.Contains("HighCpu", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Derive_NoSignals_ReturnsGenericNote()
    {
        var inc = MakeIncident(DateTimeOffset.UtcNow);
        var causes = RootCauseHeuristics.Derive(inc, plan: null, site: null, dbs: Array.Empty<DatabaseHealth>());
        causes.Should().NotBeEmpty();
    }
}
