using System.ComponentModel;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Server;

namespace AzureIncidentInvestigator;

[McpServerToolType]
public static class TelemetryTools
{
    [McpServerTool(Name = "get_top_exceptions")]
    [Description("List top exception groups from Application Insights within a bounded time window.")]
    public static Task<object> GetTopExceptions(
        AppInsightsQueryService ai,
        ToolInputValidator validator,
        ToolRateLimiter limiter,
        ILogger<ToolMarker> log,
        [Description("ISO-8601 UTC start. Optional; defaults to 24h before end.")] DateTimeOffset? startTimeUtc = null,
        [Description("ISO-8601 UTC end. Optional; defaults to now.")] DateTimeOffset? endTimeUtc = null,
        [Description("Maximum items to return (1-100). Default 20.")] int top = 20,
        CancellationToken ct = default)
        => ToolExecution.RunAsync("get_top_exceptions", limiter, log, ct, async () =>
        {
            var window = validator.NormalizeWindow(startTimeUtc, endTimeUtc);
            var clampedTop = validator.ClampTop(top);
            var result = await ai.GetTopExceptionsAsync(window, clampedTop, ct);
            return new { exceptions = result };
        });

    [McpServerTool(Name = "get_failed_dependencies")]
    [Description("List failed dependencies (external calls) from Application Insights within a bounded time window.")]
    public static Task<object> GetFailedDependencies(
        AppInsightsQueryService ai,
        ToolInputValidator validator,
        ToolRateLimiter limiter,
        ILogger<ToolMarker> log,
        [Description("ISO-8601 UTC start. Optional; defaults to 24h before end.")] DateTimeOffset? startTimeUtc = null,
        [Description("ISO-8601 UTC end. Optional; defaults to now.")] DateTimeOffset? endTimeUtc = null,
        [Description("Maximum items to return (1-100). Default 20.")] int top = 20,
        CancellationToken ct = default)
        => ToolExecution.RunAsync("get_failed_dependencies", limiter, log, ct, async () =>
        {
            var window = validator.NormalizeWindow(startTimeUtc, endTimeUtc);
            var clampedTop = validator.ClampTop(top);
            var result = await ai.GetFailedDependenciesAsync(window, clampedTop, ct);
            return new { dependencies = result };
        });
}
