using Azure;
using Azure.Monitor.Query;
using Azure.Monitor.Query.Models;
using Microsoft.Extensions.Options;

namespace AzureIncidentInvestigator;

public sealed class DatabaseHealthService
{
    private readonly MetricsQueryClient _client;
    private readonly IOptionsMonitor<DatabasesOptions> _options;

    public DatabaseHealthService(MetricsQueryClient client, IOptionsMonitor<DatabasesOptions> options)
    {
        _client = client;
        _options = options;
    }

    private static string[] MetricsFor(DatabaseType type) => type switch
    {
        DatabaseType.SqlDatabase => new[] { "cpu_percent", "dtu_consumption_percent", "connection_failed" },
        DatabaseType.SqlElasticPool => new[] { "cpu_percent", "dtu_consumption_percent" },
        DatabaseType.CosmosDb => new[] { "NormalizedRUConsumption", "TotalRequests" },
        DatabaseType.PostgresFlexible => new[] { "cpu_percent", "memory_percent", "active_connections" },
        DatabaseType.MySqlFlexible => new[] { "cpu_percent", "memory_percent" },
        _ => Array.Empty<string>()
    };

    public async Task<DatabaseHealth> AnalyzeAsync(AllowedDatabase allowed, TimeWindow window, CancellationToken ct)
    {
        var grain = MetricsHelpers.PickGrain(window);

        // Query each metric independently rather than in one batch: a metric that doesn't
        // exist for this database's purchasing model (e.g. dtu_consumption_percent on a
        // vCore SQL DB) makes Azure Monitor reject the ENTIRE batched request with a 400.
        // Per-metric queries let the unsupported one be skipped while the rest succeed.
        var queried = await Task.WhenAll(
            MetricsFor(allowed.Type).Select(name => TryQueryMetricAsync(allowed.ResourceId, name, grain, window, ct)));
        var metrics = queried.Where(m => m is not null).Select(m => m!).ToList();

        MetricSummary? Summarize(string name, double threshold)
        {
            var m = metrics.FirstOrDefault(x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
            if (m is null)
            {
                return null;
            }
            return MetricsHelpers.Summarize(MetricsHelpers.ToSeries(m, MetricAggregationType.Average), threshold);
        }

        var opts = _options.CurrentValue;
        var cpu = Summarize("cpu_percent", opts.CpuWarnThreshold)
                  ?? Summarize("NormalizedRUConsumption", opts.CpuWarnThreshold)
                  ?? new MetricSummary(0, 0, 0, 0, null);
        var dtu = Summarize("dtu_consumption_percent", opts.CpuWarnThreshold);
        var memory = Summarize("memory_percent", 80);
        var connections = Summarize("active_connections", 1000)
                          ?? Summarize("connection_failed", opts.ConnectionFailWarnPerMinute);

        Verdict verdict = (cpu.Max >= 95 || (dtu?.Max ?? 0) >= 95) ? Verdict.Saturated
                          : (cpu.Avg >= opts.CpuWarnThreshold) ? Verdict.Degraded
                          : Verdict.Healthy;

        return new DatabaseHealth(allowed.Key, allowed.Type, cpu, dtu, memory, connections, verdict);
    }

    public async Task<MetricSeries> GetSeriesAsync(
        AllowedDatabase allowed,
        DatabaseMetricSeriesKind kind,
        MetricAggregation aggregation,
        TimeWindow window,
        CancellationToken ct)
    {
        var azureName = AzureMetricName(allowed.Type, kind);
        if (azureName is null)
        {
            return new MetricSeries(kind.ToString(), "", Array.Empty<MetricPoint>());
        }

        var azureAgg = ToAzureAggregation(aggregation);
        var grain = MetricsHelpers.PickGrain(window);

        MetricResult? metric;
        try
        {
            Response<MetricsQueryResult> response = await AzureAuthGuard.GuardAsync(() => _client.QueryResourceAsync(
                allowed.ResourceId,
                new[] { azureName },
                new MetricsQueryOptions
                {
                    TimeRange = new QueryTimeRange(window.StartUtc, window.EndUtc),
                    Granularity = grain,
                    Aggregations = { azureAgg }
                },
                cancellationToken: ct));
            metric = response.Value.Metrics.FirstOrDefault(m => m.Name.Equals(azureName, StringComparison.OrdinalIgnoreCase));
        }
        catch (RequestFailedException ex) when (ex.Status == 400)
        {
            // Metric not supported for this resource/tier (e.g. DTU metrics on a vCore DB).
            metric = null;
        }

        return metric is null
            ? new MetricSeries(azureName, "", Array.Empty<MetricPoint>())
            : MetricsHelpers.ToSeries(metric, azureAgg);
    }

    // Queries a single metric, tolerating a 400 "metric not found" so an unsupported
    // metric is skipped rather than failing the caller. Auth failures still propagate.
    private async Task<MetricResult?> TryQueryMetricAsync(
        string resourceId, string metricName, TimeSpan grain, TimeWindow window, CancellationToken ct)
    {
        try
        {
            Response<MetricsQueryResult> response = await AzureAuthGuard.GuardAsync(() => _client.QueryResourceAsync(
                resourceId,
                new[] { metricName },
                new MetricsQueryOptions
                {
                    TimeRange = new QueryTimeRange(window.StartUtc, window.EndUtc),
                    Granularity = grain,
                    Aggregations = { MetricAggregationType.Average, MetricAggregationType.Maximum }
                },
                cancellationToken: ct));
            return response.Value.Metrics.FirstOrDefault(m => m.Name.Equals(metricName, StringComparison.OrdinalIgnoreCase));
        }
        catch (RequestFailedException ex) when (ex.Status == 400)
        {
            return null;
        }
    }

    private static string? AzureMetricName(DatabaseType type, DatabaseMetricSeriesKind kind) => (type, kind) switch
    {
        (DatabaseType.SqlDatabase, DatabaseMetricSeriesKind.Cpu) => "cpu_percent",
        (DatabaseType.SqlDatabase, DatabaseMetricSeriesKind.Dtu) => "dtu_consumption_percent",
        (DatabaseType.SqlDatabase, DatabaseMetricSeriesKind.Connections) => "connection_failed",
        (DatabaseType.SqlElasticPool, DatabaseMetricSeriesKind.Cpu) => "cpu_percent",
        (DatabaseType.SqlElasticPool, DatabaseMetricSeriesKind.Dtu) => "dtu_consumption_percent",
        (DatabaseType.CosmosDb, DatabaseMetricSeriesKind.Cpu) => "NormalizedRUConsumption",
        (DatabaseType.PostgresFlexible, DatabaseMetricSeriesKind.Cpu) => "cpu_percent",
        (DatabaseType.PostgresFlexible, DatabaseMetricSeriesKind.Memory) => "memory_percent",
        (DatabaseType.PostgresFlexible, DatabaseMetricSeriesKind.Connections) => "active_connections",
        (DatabaseType.MySqlFlexible, DatabaseMetricSeriesKind.Cpu) => "cpu_percent",
        (DatabaseType.MySqlFlexible, DatabaseMetricSeriesKind.Memory) => "memory_percent",
        _ => null
    };

    private static MetricAggregationType ToAzureAggregation(MetricAggregation a) => a switch
    {
        MetricAggregation.Average => MetricAggregationType.Average,
        MetricAggregation.Maximum => MetricAggregationType.Maximum,
        _ => MetricAggregationType.Average
    };
}
