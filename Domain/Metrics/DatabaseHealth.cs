using AzureIncidentInvestigator.Domain.Shared;

namespace AzureIncidentInvestigator.Domain.Metrics;

public sealed record DatabaseHealth(
    string Key,
    DatabaseType Type,
    MetricSummary Cpu,
    MetricSummary? Dtu,
    MetricSummary? Memory,
    MetricSummary? Connections,
    Verdict Verdict);
