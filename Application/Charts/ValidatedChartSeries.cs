using AzureIncidentInvestigator.Application.Options;
using AzureIncidentInvestigator.Domain.Charts;
using AzureIncidentInvestigator.Domain.Metrics;

namespace AzureIncidentInvestigator.Application.Charts;

/// <summary>
/// Untrusted, raw input from an MCP caller before validation.
/// One per series in a chart-render request.
/// </summary>
public sealed record ChartSeriesInput(
    string Label,
    string Metric,
    string? AppServicePlanResourceId,
    string? DatabaseKey,
    string Aggregation);

/// <summary>
/// Post-validation shape. Allowlists checked, target resolved, enums parsed.
/// Safe to pass to data fetchers.
/// </summary>
public sealed record ValidatedChartSeries(
    string Label,
    ChartMetric Metric,
    MetricAggregation Aggregation,
    string? PlanResourceId,
    AllowedDatabase? Database);
