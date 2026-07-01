using AzureIncidentInvestigator.Domain.Incidents;

namespace AzureIncidentInvestigator.Application.Abstractions;

public interface IUptimeRobotClient
{
    /// <summary>
    /// Fetches all monitors together with their downtime logs for the given window in a
    /// single UptimeRobot request. UptimeRobot's getMonitors endpoint returns per-monitor
    /// logs when logs=1 is set, so there is no need for an N+1 per-monitor call storm.
    /// </summary>
    Task<IReadOnlyList<MonitorWithLogs>> GetMonitorsWithLogsAsync(DateTimeOffset from, DateTimeOffset to, CancellationToken ct);
}
