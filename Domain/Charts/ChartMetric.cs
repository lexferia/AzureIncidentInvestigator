namespace AzureIncidentInvestigator.Domain.Charts;

/// <summary>
/// Curated set of metrics a caller can graph. Each value resolves internally
/// to a specific Azure Monitor metric on a specific resource type.
/// </summary>
public enum ChartMetric
{
    AppServicePlanCpu = 0,
    AppServicePlanMemory = 1,
    AppServicePlanHttpQueue = 2,
    DatabaseCpu = 3,
    DatabaseDtu = 4,
    DatabaseMemory = 5,
    DatabaseConnections = 6,
    // App Insights derived time-series (workspace from config; no per-series target needed)
    RequestsPerMinute = 7,
    FailedRequestsPerMinute = 8,
    ExceptionsPerMinute = 9,
    SnatSuspectedFailuresPerMinute = 10
}

public enum ChartValueType
{
    Percentage = 0,
    Count = 1
}
