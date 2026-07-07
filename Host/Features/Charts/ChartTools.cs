using System.ComponentModel;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace AzureIncidentInvestigator;

[McpServerToolType]
public static class ChartTools
{
    [McpServerTool(Name = "render_metric_chart")]
    [Description("Render a multi-series time-line chart (PNG, dark Azure-portal style) for App Service Plan and/or Database metrics. Returns the image inline plus a JSON metadata blob.")]
    public static Task<CallToolResult> RenderMetricChart(
        MetricChartService chart,
        ToolInputValidator validator,
        ToolRateLimiter limiter,
        ILogger<ToolMarker> log,
        [Description("1-4 series specs to overlay. Each series has Label, Metric (AppServicePlanCpu|AppServicePlanMemory|AppServicePlanHttpQueue|DatabaseCpu|DatabaseDtu|DatabaseMemory|DatabaseConnections|RequestsPerMinute|FailedRequestsPerMinute|ExceptionsPerMinute|SnatSuspectedFailuresPerMinute), and (for Plan/DB metrics only) either AppServicePlanResourceId (allowlisted) or DatabaseKey (allowlisted), plus Aggregation (Average|Maximum). App Insights time-series metrics don't require a per-series target.")] ChartSeriesSpec[] series,
        [Description("Optional chart title (<=256 chars; redacted before rendering).")] string? title = null,
        [Description("ISO-8601 UTC start. Optional; defaults to 24h before end.")] DateTimeOffset? startTimeUtc = null,
        [Description("ISO-8601 UTC end. Optional; defaults to now.")] DateTimeOffset? endTimeUtc = null,
        [Description("If true, also write the PNG to Reports:OutputDirectory.")] bool saveToFile = false,
        CancellationToken ct = default)
        => ToolExecution.RunCallToolAsync("render_metric_chart", limiter, log, ct, async () =>
        {
            var inputs = (series ?? Array.Empty<ChartSeriesSpec>())
                .Select(s => new ChartSeriesInput(
                    s.Label,
                    s.Metric,
                    s.AppServicePlanResourceId,
                    s.DatabaseKey,
                    s.Aggregation))
                .ToList();

            var validated = validator.ValidateChartSeries(inputs);
            validator.ValidateString(title, "title", maxLength: 256);
            var window = validator.NormalizeWindow(startTimeUtc, endTimeUtc);

            var result = await chart.RenderAsync(title, validated, window, saveToFile, ct);

            var meta = new
            {
                seriesCount = result.SeriesCount,
                pointCount = result.TotalPointCount,
                savedPath = result.SavedPath
            };

            return new CallToolResult
            {
                Content =
                {
                    ImageContentBlock.FromBytes(result.Png, "image/png"),
                    new TextContentBlock { Text = JsonSerializer.Serialize(meta) }
                }
            };
        });
}
