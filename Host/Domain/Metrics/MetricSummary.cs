namespace AzureIncidentInvestigator.Domain.Metrics;

public sealed record MetricSummary(
    double Avg,
    double P95,
    double Max,
    int MinutesOverThreshold,
    DateTimeOffset? HottestAtUtc);
