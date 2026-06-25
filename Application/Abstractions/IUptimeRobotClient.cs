using AzureIncidentInvestigator.Domain.Incidents;

namespace AzureIncidentInvestigator.Application.Abstractions;

public interface IUptimeRobotClient
{
    Task<IReadOnlyList<UptimeMonitor>> GetMonitorsAsync(CancellationToken ct);
    Task<IReadOnlyList<MonitorLog>> GetMonitorLogsAsync(long monitorId, DateTimeOffset from, DateTimeOffset to, CancellationToken ct);
}
