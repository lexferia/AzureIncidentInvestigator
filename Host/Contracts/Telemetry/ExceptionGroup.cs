
namespace AzureIncidentInvestigator;

public sealed record ExceptionGroup(
    SanitizedString Type,
    SanitizedString Message,
    long Count,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc,
    IReadOnlyList<SanitizedString> Operations);
