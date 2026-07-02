namespace AzureIncidentInvestigator.Domain.Metrics;

public sealed record MetricPoint(DateTimeOffset AtUtc, double Value);

public sealed record MetricSeries(string Name, string Unit, IReadOnlyList<MetricPoint> Points);
