namespace AzureIncidentInvestigator.Domain.Metrics;

public enum ScaleDirection { Up, Down }

public sealed record ScaleEvent(DateTimeOffset AtUtc, int FromCount, int ToCount, ScaleDirection Direction);

public sealed record InstanceCountAnalysis(
    int StartCount,
    int EndCount,
    IReadOnlyList<ScaleEvent> ScaleEvents);
