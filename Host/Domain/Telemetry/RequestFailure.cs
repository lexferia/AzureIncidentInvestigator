using AzureIncidentInvestigator.Domain.Shared;

namespace AzureIncidentInvestigator.Domain.Telemetry;

public sealed record RequestFailure(
    SanitizedString Name,
    long Count,
    IReadOnlyList<SanitizedString> ResultCodes,
    double AvgDurationMs);
