using System.ComponentModel;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Server;

namespace AzureIncidentInvestigator;

[McpServerToolType]
public static class IncidentTools
{
    [McpServerTool(Name = "get_recent_downtime_incidents")]
    [Description("List recent downtime incidents from UptimeRobot (days clamped to 1-30).")]
    public static Task<object> GetRecentIncidents(
        IncidentService incidents,
        ToolInputValidator validator,
        ToolRateLimiter limiter,
        ILogger<ToolMarker> log,
        [Description("How many days back to look (1-30). Default 7.")] int days = 7,
        CancellationToken ct = default)
        => ToolExecution.RunAsync("get_recent_downtime_incidents", limiter, log, ct, async () =>
        {
            var clampedDays = validator.ClampDays(days);
            var results = await incidents.GetRecentIncidentsAsync(clampedDays, ct);
            return new { incidents = results };
        });
}
