using Azure;
using Azure.Monitor.Query;
using Azure.Monitor.Query.Models;
using Microsoft.Extensions.Options;
using AzureIncidentInvestigator.Application.Abstractions;
using AzureIncidentInvestigator.Application.Options;
using AzureIncidentInvestigator.Domain.Metrics;
using AzureIncidentInvestigator.Domain.Shared;

namespace AzureIncidentInvestigator.Infrastructure.AzureMonitor;

internal sealed class AppServicePlanMetricsService : IAppServicePlanMetricsService
{
    // App Service Plan (Microsoft.Web/serverfarms) standard metrics.
    private static readonly string[] MetricNames =
    {
        "CpuPercentage", "MemoryPercentage", "HttpQueueLength", "DiskQueueLength"
    };

    private readonly MetricsQueryClient _client;
    private readonly IOptionsMonitor<AppServicePlansOptions> _options;

    public AppServicePlanMetricsService(MetricsQueryClient client, IOptionsMonitor<AppServicePlansOptions> options)
    {
        _client = client;
        _options = options;
    }

    public async Task<AppServicePlanHealth> AnalyzeAsync(string allowedResourceId, TimeWindow window, CancellationToken ct)
    {
        var grain = MetricsHelpers.PickGrain(window);

        Response<MetricsQueryResult> response = await _client.QueryResourceAsync(
            allowedResourceId,
            MetricNames,
            new MetricsQueryOptions
            {
                TimeRange = new QueryTimeRange(window.StartUtc, window.EndUtc),
                Granularity = grain,
                Aggregations = { MetricAggregationType.Average, MetricAggregationType.Maximum }
            },
            cancellationToken: ct);

        MetricSeries Series(string name, MetricAggregationType agg)
        {
            var m = response.Value.Metrics.FirstOrDefault(x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
            return m is null
                ? new MetricSeries(name, "", Array.Empty<MetricPoint>())
                : MetricsHelpers.ToSeries(m, agg);
        }

        var opts = _options.CurrentValue;
        var cpuSeries = Series("CpuPercentage", MetricAggregationType.Average);
        var memSeries = Series("MemoryPercentage", MetricAggregationType.Average);
        var queueSeries = Series("HttpQueueLength", MetricAggregationType.Average);
        var diskSeries = Series("DiskQueueLength", MetricAggregationType.Average);

        var cpu = MetricsHelpers.Summarize(cpuSeries, opts.CpuWarnThreshold);
        var mem = MetricsHelpers.Summarize(memSeries, opts.MemoryWarnThreshold);
        var queue = MetricsHelpers.Summarize(queueSeries, 100);
        var disk = MetricsHelpers.Summarize(diskSeries, 100);

        // Instance count is not a standard serverfarms Azure Monitor metric, so scale
        // events are derived from CPU sample cadence only when an explicit instance series
        // is unavailable; left empty here to avoid querying an unsupported metric name.
        var instances = new InstanceCountAnalysis(0, 0, Array.Empty<ScaleEvent>());

        var verdict = MetricsHelpers.ComputeVerdict(cpu, mem, opts.CpuWarnThreshold, opts.MemoryWarnThreshold);

        return new AppServicePlanHealth(allowedResourceId, cpu, mem, queue, disk, instances, verdict);
    }

    public async Task<MetricSeries> GetSeriesAsync(
        string allowedResourceId,
        PlanMetricSeriesKind kind,
        MetricAggregation aggregation,
        TimeWindow window,
        CancellationToken ct)
    {
        var azureName = AzureMetricName(kind);
        var azureAgg = ToAzureAggregation(aggregation);
        var grain = MetricsHelpers.PickGrain(window);

        Response<MetricsQueryResult> response = await _client.QueryResourceAsync(
            allowedResourceId,
            new[] { azureName },
            new MetricsQueryOptions
            {
                TimeRange = new QueryTimeRange(window.StartUtc, window.EndUtc),
                Granularity = grain,
                Aggregations = { azureAgg }
            },
            cancellationToken: ct);

        var metric = response.Value.Metrics.FirstOrDefault(m => m.Name.Equals(azureName, StringComparison.OrdinalIgnoreCase));
        return metric is null
            ? new MetricSeries(azureName, "", Array.Empty<MetricPoint>())
            : MetricsHelpers.ToSeries(metric, azureAgg);
    }

    private static string AzureMetricName(PlanMetricSeriesKind kind) => kind switch
    {
        PlanMetricSeriesKind.Cpu => "CpuPercentage",
        PlanMetricSeriesKind.Memory => "MemoryPercentage",
        PlanMetricSeriesKind.HttpQueue => "HttpQueueLength",
        PlanMetricSeriesKind.DiskQueue => "DiskQueueLength",
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown plan series kind.")
    };

    private static MetricAggregationType ToAzureAggregation(MetricAggregation a) => a switch
    {
        MetricAggregation.Average => MetricAggregationType.Average,
        MetricAggregation.Maximum => MetricAggregationType.Maximum,
        _ => MetricAggregationType.Average
    };
}
