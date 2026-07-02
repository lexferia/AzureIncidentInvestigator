using AzureIncidentInvestigator.Domain.Shared;

namespace AzureIncidentInvestigator.Domain.Metrics;

public sealed record RestartEvent(DateTimeOffset AtUtc, string OperationName, SanitizedString Description);
