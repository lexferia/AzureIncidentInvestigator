
namespace AzureIncidentInvestigator;

public sealed class IncidentService
{
    private readonly IUptimeRobotClient _ur;

    public IncidentService(IUptimeRobotClient ur) => _ur = ur;

    public async Task<IReadOnlyList<Incident>> GetRecentIncidentsAsync(int days, CancellationToken ct)
    {
        var from = DateTimeOffset.UtcNow.AddDays(-days);
        var to = DateTimeOffset.UtcNow;
        var monitorsWithLogs = await _ur.GetMonitorsWithLogsAsync(from, to, ct);
        var incidents = new List<Incident>();

        foreach (var (monitor, logs) in monitorsWithLogs)
        {
            foreach (var log in logs.Where(l => l.Type == 1))
            {
                var endUtc = log.Duration.HasValue ? log.AtUtc.AddSeconds(log.Duration.Value) : (DateTimeOffset?)null;
                incidents.Add(new Incident(
                    $"{monitor.Id}:{log.LogId}",
                    monitor.Id,
                    monitor.FriendlyName,
                    monitor.Url,
                    log.AtUtc,
                    endUtc,
                    log.Duration,
                    log.Reason));
            }
        }

        return incidents.OrderByDescending(i => i.DownStartUtc).ToList();
    }

    public async Task<Incident?> GetIncidentByIdAsync(string incidentId, CancellationToken ct)
    {
        var parts = incidentId.Split(':');
        if (parts.Length != 2 || !long.TryParse(parts[0], out var monitorId) || !long.TryParse(parts[1], out var logId))
        {
            return null;
        }

        var monitorsWithLogs = await _ur.GetMonitorsWithLogsAsync(
            DateTimeOffset.UtcNow.AddDays(-30), DateTimeOffset.UtcNow.AddMinutes(1), ct);
        var match = monitorsWithLogs.FirstOrDefault(m => m.Monitor.Id == monitorId);
        if (match is null)
        {
            return null;
        }

        var monitor = match.Monitor;
        var log = match.Logs.FirstOrDefault(l => l.LogId == logId);
        if (log is null)
        {
            return null;
        }

        var endUtc = log.Duration.HasValue ? log.AtUtc.AddSeconds(log.Duration.Value) : (DateTimeOffset?)null;
        return new Incident(incidentId, monitor.Id, monitor.FriendlyName, monitor.Url, log.AtUtc, endUtc, log.Duration, log.Reason);
    }
}
