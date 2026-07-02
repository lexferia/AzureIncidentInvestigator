namespace AzureIncidentInvestigator;

public sealed record AppServiceSiteHealth(
    string ResourceId,
    IReadOnlyList<RestartEvent> Restarts,
    SnatExhaustionFinding Snat);
