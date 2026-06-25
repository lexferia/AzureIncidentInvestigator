using AzureIncidentInvestigator.Domain.Shared;

namespace AzureIncidentInvestigator.Domain.Telemetry;

public sealed record DependencyFailure(
    SanitizedString Target,
    SanitizedString Type,
    long Count,
    double AvgDurationMs,
    IReadOnlyList<SanitizedString> ResultCodes);
