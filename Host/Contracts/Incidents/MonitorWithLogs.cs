namespace AzureIncidentInvestigator;

public sealed record MonitorWithLogs(
    UptimeMonitor Monitor,
    IReadOnlyList<MonitorLog> Logs);
