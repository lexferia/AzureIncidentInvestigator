namespace AzureIncidentInvestigator.Domain.Metrics;

public sealed record AppServiceSiteHealth(
    string ResourceId,
    IReadOnlyList<RestartEvent> Restarts,
    SnatExhaustionFinding Snat);
