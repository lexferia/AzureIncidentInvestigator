using System.ComponentModel;

namespace AzureIncidentInvestigator;

/// <summary>
/// Raw, untrusted MCP input shape for a single chart series.
/// Mapped to <see cref="Application.Charts.ChartSeriesInput"/> for validation,
/// which produces an <see cref="Application.Charts.ValidatedChartSeries"/>.
/// </summary>
public sealed class ChartSeriesSpec
{
    [Description("Series label shown in the legend (1-64 chars, redacted).")]
    public string Label { get; set; } = "";

    [Description("Metric to plot. Plan/DB metrics: AppServicePlanCpu, AppServicePlanMemory, AppServicePlanHttpQueue, DatabaseCpu, DatabaseDtu, DatabaseMemory, DatabaseConnections. App Insights time-series (workspace-wide, no per-series target): RequestsPerMinute, FailedRequestsPerMinute, ExceptionsPerMinute, SnatSuspectedFailuresPerMinute.")]
    public string Metric { get; set; } = "";

    [Description("Required for AppServicePlan* metrics only. Must be in AppServicePlans:AllowedResourceIds.")]
    public string? AppServicePlanResourceId { get; set; }

    [Description("Required for Database* metrics only. Must match Databases:Allowed[].Key.")]
    public string? DatabaseKey { get; set; }

    [Description("Aggregation: Average (default) or Maximum.")]
    public string Aggregation { get; set; } = "Average";
}
