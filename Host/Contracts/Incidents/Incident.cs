namespace AzureIncidentInvestigator;

public sealed record Incident(
    string Id,
    long MonitorId,
    string MonitorName,
    string MonitorUrl,
    DateTimeOffset DownStartUtc,
    DateTimeOffset? DownEndUtc,
    int? DurationSeconds,
    string? Reason);
