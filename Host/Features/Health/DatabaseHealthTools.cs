using System.ComponentModel;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Server;

namespace AzureIncidentInvestigator;

[McpServerToolType]
public static class DatabaseHealthTools
{
    [McpServerTool(Name = "analyze_database_health")]
    [Description("Analyze database health (CPU/DTU/memory/connections) for a database key configured in Databases:Allowed.")]
    public static Task<object> AnalyzeDatabase(
        DatabaseHealthService svc,
        ToolInputValidator validator,
        ToolRateLimiter limiter,
        ILogger<ToolMarker> log,
        [Description("Database key as configured in Databases:Allowed[].Key.")] string databaseKey,
        [Description("ISO-8601 UTC start. Optional; defaults to 24h before end.")] DateTimeOffset? startTimeUtc = null,
        [Description("ISO-8601 UTC end. Optional; defaults to now.")] DateTimeOffset? endTimeUtc = null,
        CancellationToken ct = default)
        => ToolExecution.RunAsync("analyze_database_health", limiter, log, ct, async () =>
        {
            var allowed = validator.ValidateDatabaseKey(databaseKey);
            var window = validator.NormalizeWindow(startTimeUtc, endTimeUtc);
            return await svc.AnalyzeAsync(allowed, window, ct);
        });
}
