using AzureIncidentInvestigator.Domain.Crawlers;
using AzureIncidentInvestigator.Domain.Metrics;
using AzureIncidentInvestigator.Domain.Shared;
using AzureIncidentInvestigator.Domain.Telemetry;

namespace AzureIncidentInvestigator.Application.Abstractions;

public interface IAppInsightsQueryService
{
    Task<IReadOnlyList<ExceptionGroup>> GetTopExceptionsAsync(TimeWindow w, int top, CancellationToken ct);
    Task<IReadOnlyList<RequestFailure>> GetFailedRequestsAsync(TimeWindow w, int top, CancellationToken ct);
    Task<IReadOnlyList<DependencyFailure>> GetFailedDependenciesAsync(TimeWindow w, int top, CancellationToken ct);
    Task<IReadOnlyList<UserAgentRollup>> GetTopUserAgentsAsync(TimeWindow w, int top, CancellationToken ct);
    Task<IReadOnlyList<IpRollup>> GetTopClientIpsAsync(TimeWindow w, int top, CancellationToken ct);
    Task<IReadOnlyDictionary<string, long>> GetStatusCodeBreakdownAsync(TimeWindow w, CancellationToken ct);

    /// <summary>
    /// Surface (10-min, IP, country, UA) tuples exceeding the burst threshold. Authoritative bad-crawler signal.
    /// </summary>
    Task<IReadOnlyList<BurstyCrawlerEvent>> GetBurstyCrawlerActivityAsync(TimeWindow w, int minRequestsPerBin, CancellationToken ct);

    /// <summary>
    /// Bucketed time-series (count per bin) suitable for charting. Grain is auto-selected from the window.
    /// </summary>
    Task<MetricSeries> GetTimeSeriesAsync(AppInsightsSeriesKind kind, TimeWindow w, CancellationToken ct);
}

public sealed record UserAgentRollup(string UserAgent, long RequestCount, long NotFoundCount);
public sealed record IpRollup(string IpBucket, long RequestCount);
