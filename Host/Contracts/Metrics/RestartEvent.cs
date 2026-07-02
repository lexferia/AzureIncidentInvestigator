
namespace AzureIncidentInvestigator;

public sealed record RestartEvent(DateTimeOffset AtUtc, string OperationName, SanitizedString Description);
