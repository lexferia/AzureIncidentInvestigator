namespace AzureIncidentInvestigator;

public sealed record UptimeMonitor(
    long Id,
    string FriendlyName,
    string Url,
    MonitorStatus Status,
    int IntervalSeconds);
