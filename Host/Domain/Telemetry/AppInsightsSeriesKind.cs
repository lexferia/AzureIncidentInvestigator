namespace AzureIncidentInvestigator.Domain.Telemetry;

/// <summary>
/// Kinds of time-series the AppInsights query service can produce for charting.
/// Each maps to a parameterized KQL template binned by minute.
/// </summary>
public enum AppInsightsSeriesKind
{
    Requests = 0,
    FailedRequests = 1,
    Exceptions = 2,
    SnatSuspectedFailures = 3
}
