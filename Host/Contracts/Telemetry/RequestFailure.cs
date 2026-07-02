
namespace AzureIncidentInvestigator;

public sealed record RequestFailure(
    SanitizedString Name,
    long Count,
    IReadOnlyList<SanitizedString> ResultCodes,
    double AvgDurationMs);
