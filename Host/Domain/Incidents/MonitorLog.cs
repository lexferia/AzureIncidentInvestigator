namespace AzureIncidentInvestigator.Domain.Incidents;

public sealed record MonitorLog(
    long MonitorId,
    long LogId,
    int Type,
    DateTimeOffset AtUtc,
    string? Reason,
    int? Duration);
