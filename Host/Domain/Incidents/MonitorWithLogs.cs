namespace AzureIncidentInvestigator.Domain.Incidents;

public sealed record MonitorWithLogs(
    UptimeMonitor Monitor,
    IReadOnlyList<MonitorLog> Logs);
