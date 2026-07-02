using AzureIncidentInvestigator.Domain.Shared;

namespace AzureIncidentInvestigator.Domain.Telemetry;

public sealed record ExceptionGroup(
    SanitizedString Type,
    SanitizedString Message,
    long Count,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc,
    IReadOnlyList<SanitizedString> Operations);
