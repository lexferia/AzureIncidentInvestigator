using AzureIncidentInvestigator.Application.Options;
using AzureIncidentInvestigator.Domain.Metrics;
using AzureIncidentInvestigator.Domain.Shared;

namespace AzureIncidentInvestigator.Application.Abstractions;

public interface IDatabaseHealthService
{
    Task<DatabaseHealth> AnalyzeAsync(AllowedDatabase allowed, TimeWindow window, CancellationToken ct);

    Task<MetricSeries> GetSeriesAsync(
        AllowedDatabase allowed,
        DatabaseMetricSeriesKind kind,
        MetricAggregation aggregation,
        TimeWindow window,
        CancellationToken ct);
}
