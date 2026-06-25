using AzureIncidentInvestigator.Domain.Metrics;
using AzureIncidentInvestigator.Domain.Shared;

namespace AzureIncidentInvestigator.Application.Abstractions;

public interface IAppServicePlanMetricsService
{
    Task<AppServicePlanHealth> AnalyzeAsync(string allowedResourceId, TimeWindow window, CancellationToken ct);

    Task<MetricSeries> GetSeriesAsync(
        string allowedResourceId,
        PlanMetricSeriesKind kind,
        MetricAggregation aggregation,
        TimeWindow window,
        CancellationToken ct);
}
