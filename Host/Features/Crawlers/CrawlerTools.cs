using System.ComponentModel;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Server;

namespace AzureIncidentInvestigator;

[McpServerToolType]
public static class CrawlerTools
{
    [McpServerTool(Name = "detect_bad_crawlers")]
    [Description("Detect suspicious or abusive crawlers within a bounded time window (<= 7 days). Defaults to the last 24h.")]
    public static Task<object> DetectBadCrawlers(
        CrawlerDetectionService crawlers,
        ToolInputValidator validator,
        ToolRateLimiter limiter,
        ILogger<ToolMarker> log,
        [Description("ISO-8601 UTC start. Optional; defaults to 24h before end.")] DateTimeOffset? startTimeUtc = null,
        [Description("ISO-8601 UTC end. Optional; defaults to now.")] DateTimeOffset? endTimeUtc = null,
        CancellationToken ct = default)
        => ToolExecution.RunAsync("detect_bad_crawlers", limiter, log, ct, async () =>
        {
            var window = validator.NormalizeWindow(startTimeUtc, endTimeUtc);
            return await crawlers.DetectAsync(window, ct);
        });
}
