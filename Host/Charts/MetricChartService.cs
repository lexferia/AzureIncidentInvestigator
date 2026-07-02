using Microsoft.Extensions.Options;
using AzureIncidentInvestigator.Application.Abstractions;
using AzureIncidentInvestigator.Application.Charts;
using AzureIncidentInvestigator.Infrastructure.AzureMonitor;
using AzureIncidentInvestigator.Application.Options;
using AzureIncidentInvestigator.Domain.Charts;
using AzureIncidentInvestigator.Domain.Metrics;
using AzureIncidentInvestigator.Domain.Shared;
using AzureIncidentInvestigator.Domain.Telemetry;

namespace AzureIncidentInvestigator.Host.Charts;

/// <summary>
/// Fetches metric series for each validated chart spec, then asks the renderer for a PNG.
/// Stateless; safe as a singleton.
/// </summary>
public sealed class MetricChartService
{
    private const int MaxPointsPerSeries = 1000;

    private readonly AppServicePlanMetricsService _plans;
    private readonly DatabaseHealthService _dbs;
    private readonly AppInsightsQueryService _ai;
    private readonly IOptionsMonitor<ReportsOptions> _reportOpts;
    private readonly ITextRedactor _redactor;

    public MetricChartService(
        AppServicePlanMetricsService plans,
        DatabaseHealthService dbs,
        AppInsightsQueryService ai,
        IOptionsMonitor<ReportsOptions> reportOpts,
        ITextRedactor redactor)
    {
        _plans = plans;
        _dbs = dbs;
        _ai = ai;
        _reportOpts = reportOpts;
        _redactor = redactor;
    }

    public async Task<MetricChartResult> RenderAsync(
        string? title,
        IReadOnlyList<ValidatedChartSeries> series,
        TimeWindow window,
        bool saveToFile,
        CancellationToken ct)
    {
        var fetchTasks = series.Select(s => FetchSeriesAsync(s, window, ct)).ToArray();
        var fetched = await Task.WhenAll(fetchTasks);

        var renderSeries = new List<MetricChartRenderer.RenderSeries>(fetched.Length);
        var totalPoints = 0;
        for (var i = 0; i < fetched.Length; i++)
        {
            var (spec, raw) = fetched[i];
            var points = raw.Points;
            if (points.Count > MaxPointsPerSeries)
            {
                points = points.Take(MaxPointsPerSeries).ToList();
            }
            renderSeries.Add(new MetricChartRenderer.RenderSeries(
                _redactor.Redact(spec.Label),
                points.Select(p => p.AtUtc.UtcDateTime).ToArray(),
                points.Select(p => p.Value).ToArray(),
                MetricChartRenderer.PaletteColor(i)));
            totalPoints += points.Count;
        }

        var safeTitle = _redactor.Redact(title ?? DefaultTitle(series, window));
        var valueType = DeriveValueType(series);

        var png = MetricChartRenderer.RenderPng(safeTitle, valueType, renderSeries);

        string? savedPath = null;
        if (saveToFile)
        {
            savedPath = await SaveAsync(png, ct);
        }

        return new MetricChartResult(png, savedPath, renderSeries.Count, totalPoints);
    }

    private async Task<(ValidatedChartSeries Spec, MetricSeries Raw)> FetchSeriesAsync(
        ValidatedChartSeries s, TimeWindow window, CancellationToken ct)
    {
        var raw = s.Metric switch
        {
            ChartMetric.AppServicePlanCpu => await _plans.GetSeriesAsync(s.PlanResourceId!, PlanMetricSeriesKind.Cpu, s.Aggregation, window, ct),
            ChartMetric.AppServicePlanMemory => await _plans.GetSeriesAsync(s.PlanResourceId!, PlanMetricSeriesKind.Memory, s.Aggregation, window, ct),
            ChartMetric.AppServicePlanHttpQueue => await _plans.GetSeriesAsync(s.PlanResourceId!, PlanMetricSeriesKind.HttpQueue, s.Aggregation, window, ct),
            ChartMetric.DatabaseCpu => await _dbs.GetSeriesAsync(s.Database!, DatabaseMetricSeriesKind.Cpu, s.Aggregation, window, ct),
            ChartMetric.DatabaseDtu => await _dbs.GetSeriesAsync(s.Database!, DatabaseMetricSeriesKind.Dtu, s.Aggregation, window, ct),
            ChartMetric.DatabaseMemory => await _dbs.GetSeriesAsync(s.Database!, DatabaseMetricSeriesKind.Memory, s.Aggregation, window, ct),
            ChartMetric.DatabaseConnections => await _dbs.GetSeriesAsync(s.Database!, DatabaseMetricSeriesKind.Connections, s.Aggregation, window, ct),
            ChartMetric.RequestsPerMinute => await _ai.GetTimeSeriesAsync(AppInsightsSeriesKind.Requests, window, ct),
            ChartMetric.FailedRequestsPerMinute => await _ai.GetTimeSeriesAsync(AppInsightsSeriesKind.FailedRequests, window, ct),
            ChartMetric.ExceptionsPerMinute => await _ai.GetTimeSeriesAsync(AppInsightsSeriesKind.Exceptions, window, ct),
            ChartMetric.SnatSuspectedFailuresPerMinute => await _ai.GetTimeSeriesAsync(AppInsightsSeriesKind.SnatSuspectedFailures, window, ct),
            _ => new MetricSeries(s.Metric.ToString(), "", Array.Empty<MetricPoint>())
        };
        return (s, raw);
    }

    private async Task<string> SaveAsync(byte[] png, CancellationToken ct)
    {
        var rootRaw = Environment.ExpandEnvironmentVariables(_reportOpts.CurrentValue.OutputDirectory);
        var root = Path.GetFullPath(rootRaw);
        Directory.CreateDirectory(root);

        var fileName = $"chart-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.png";
        var fullPath = Path.GetFullPath(Path.Combine(root, fileName));

        if (!fullPath.StartsWith(root, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Resolved chart path escapes configured output directory.");
        }

        await File.WriteAllBytesAsync(fullPath, png, ct);
        return fullPath;
    }

    private static string DefaultTitle(IReadOnlyList<ValidatedChartSeries> series, TimeWindow w) =>
        $"{string.Join(" / ", series.Select(s => s.Metric))}   {w.StartUtc:u} → {w.EndUtc:u}";

    /// <summary>
    /// Choose percentage axis if every series is naturally a percent; otherwise count axis.
    /// Mixing percent + count in one chart is allowed but the axis just shows numbers.
    /// </summary>
    private static ChartValueType DeriveValueType(IReadOnlyList<ValidatedChartSeries> series) =>
        series.All(IsPercentageMetric) ? ChartValueType.Percentage : ChartValueType.Count;

    private static bool IsPercentageMetric(ValidatedChartSeries s) => s.Metric switch
    {
        ChartMetric.AppServicePlanCpu or
        ChartMetric.AppServicePlanMemory or
        ChartMetric.DatabaseCpu or
        ChartMetric.DatabaseDtu or
        ChartMetric.DatabaseMemory => true,
        _ => false
    };
}

public sealed record MetricChartResult(byte[] Png, string? SavedPath, int SeriesCount, int TotalPointCount);
