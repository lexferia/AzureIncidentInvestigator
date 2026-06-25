using AzureIncidentInvestigator.Domain.Shared;

namespace AzureIncidentInvestigator.Domain.Metrics;

public sealed record SnatTargetFailure(SanitizedString Target, long Failures, DateTimeOffset PeakMinuteUtc);

public sealed record SnatExhaustionFinding(
    bool Suspected,
    long TotalSuspectFailures,
    IReadOnlyList<SnatTargetFailure> ByTarget,
    DateTimeOffset? PeakMinuteUtc);
