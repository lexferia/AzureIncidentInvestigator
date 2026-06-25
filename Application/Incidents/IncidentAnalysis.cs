using AzureIncidentInvestigator.Domain.Crawlers;
using AzureIncidentInvestigator.Domain.Diagnostics;
using AzureIncidentInvestigator.Domain.Incidents;
using AzureIncidentInvestigator.Domain.Metrics;
using AzureIncidentInvestigator.Domain.Shared;
using AzureIncidentInvestigator.Domain.Telemetry;

namespace AzureIncidentInvestigator.Application.Incidents;

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
