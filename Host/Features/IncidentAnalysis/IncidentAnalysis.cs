
namespace AzureIncidentInvestigator;

public sealed record IncidentAnalysis(
    Incident Incident,
    SanitizedString Summary,
    IReadOnlyList<ExceptionGroup> TopExceptions,
    IReadOnlyList<DependencyFailure> FailedDependencies,
    IReadOnlyList<SuspiciousCrawler> SuspiciousCrawlers,
    AppServicePlanHealth? AppServicePlanHealth,
    AppServiceSiteHealth? AppServiceSiteHealth,
    IReadOnlyList<DatabaseHealth> DatabaseHealth,
    IReadOnlyList<DetectorResult> AppServiceDiagnostics,
    IReadOnlyList<string> PossibleRootCauses,
    int RedactedItemsCount);
