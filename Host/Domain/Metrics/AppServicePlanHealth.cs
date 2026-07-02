using AzureIncidentInvestigator.Domain.Shared;

namespace AzureIncidentInvestigator.Domain.Metrics;

public sealed record AppServicePlanHealth(
    string ResourceId,
    MetricSummary Cpu,
    MetricSummary Memory,
    MetricSummary HttpQueue,
    MetricSummary DiskQueue,
    InstanceCountAnalysis InstanceCount,
    Verdict Verdict);
