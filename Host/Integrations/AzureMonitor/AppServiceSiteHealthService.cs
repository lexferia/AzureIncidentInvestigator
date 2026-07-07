using Azure;
using Azure.Monitor.Query;
using Azure.Monitor.Query.Models;
using Microsoft.Extensions.Options;

namespace AzureIncidentInvestigator;

public sealed class AppServiceSiteHealthService
{
    private readonly LogsQueryClient _client;
    private readonly AppServiceDetectorService _detectors;
    private readonly IOptionsMonitor<AppInsightsOptions> _options;
    private readonly ITextRedactor _redactor;

    public AppServiceSiteHealthService(
        LogsQueryClient client,
        AppServiceDetectorService detectors,
        IOptionsMonitor<AppInsightsOptions> options,
        ITextRedactor redactor)
    {
        _client = client;
        _detectors = detectors;
        _options = options;
        _redactor = redactor;
    }

    /// <param name="snatDetector">
    /// Optional pre-fetched SNAT Port Exhaustion detector result. When null, this method queries
    /// it. Callers that already fetched it (e.g. analyze_incident) pass it to avoid a duplicate call.
    /// </param>
    public async Task<AppServiceSiteHealth> AnalyzeAsync(
        string allowedSiteResourceId,
        TimeWindow window,
        CancellationToken ct,
        DetectorResult? snatDetector = null)
    {
        var restartsTask = GetRestartsAsync(allowedSiteResourceId, window, ct);
        var depsTask = GetOutboundDependencyFailuresAsync(window, ct);

        // SNAT verdict comes from the authoritative platform detector, never from dependency failures.
        snatDetector ??= await _detectors.QueryAsync(allowedSiteResourceId, DetectorKind.SnatPortExhaustion, window, ct);
        var snat = SnatEvaluator.Evaluate(snatDetector);

        await Task.WhenAll(restartsTask, depsTask);
        return new AppServiceSiteHealth(allowedSiteResourceId, await restartsTask, snat, await depsTask);
    }

    public async Task<IReadOnlyList<RestartEvent>> GetRestartsAsync(string allowedSiteResourceId, TimeWindow window, CancellationToken ct)
    {
        var workspaceId = _options.CurrentValue.WorkspaceId;
        if (string.IsNullOrWhiteSpace(workspaceId))
        {
            return Array.Empty<RestartEvent>();
        }

        Response<LogsQueryResult> response = await AzureAuthGuard.GuardAsync(() => _client.QueryWorkspaceAsync(
            workspaceId,
            KqlTemplate.AppServiceRestarts,
            new QueryTimeRange(window.StartUtc, window.EndUtc),
            cancellationToken: ct));

        var table = response.Value.Table;
        return table.Rows.Select(row => new RestartEvent(
            AsDateTimeOffset(row[0]),
            row[1]?.ToString() ?? "",
            _redactor.Wrap(row[2]?.ToString() ?? ""))).ToList();
    }

    /// <summary>
    /// Failed outbound dependency calls grouped by target (App Insights). Application-level signal,
    /// NOT a SNAT verdict — kept separate so it can never be mistaken for SNAT port exhaustion.
    /// </summary>
    public async Task<OutboundDependencyFailures> GetOutboundDependencyFailuresAsync(TimeWindow window, CancellationToken ct)
    {
        var workspaceId = _options.CurrentValue.WorkspaceId;
        if (string.IsNullOrWhiteSpace(workspaceId))
        {
            return new OutboundDependencyFailures(0, Array.Empty<OutboundDependencyTarget>(), null);
        }

        Response<LogsQueryResult> response = await AzureAuthGuard.GuardAsync(() => _client.QueryWorkspaceAsync(
            workspaceId,
            KqlTemplate.OutboundDependencyFailures,
            new QueryTimeRange(window.StartUtc, window.EndUtc),
            cancellationToken: ct));

        var rows = response.Value.Table.Rows;
        if (rows.Count == 0)
        {
            return new OutboundDependencyFailures(0, Array.Empty<OutboundDependencyTarget>(), null);
        }

        long total = 0;
        DateTimeOffset peak = DateTimeOffset.MinValue;
        long peakValue = 0;
        var byTarget = new Dictionary<string, (long Failures, DateTimeOffset PeakMinute, long PeakCount)>();

        foreach (var row in rows)
        {
            var ts = AsDateTimeOffset(row[0]);
            var target = row[1]?.ToString() ?? "unknown";
            var failures = Convert.ToInt64(row[2]);
            total += failures;
            if (failures > peakValue)
            {
                peakValue = failures;
                peak = ts;
            }

            if (byTarget.TryGetValue(target, out var existing))
            {
                var (newPeakMinute, newPeakCount) = failures > existing.PeakCount
                    ? (ts, failures)
                    : (existing.PeakMinute, existing.PeakCount);
                byTarget[target] = (existing.Failures + failures, newPeakMinute, newPeakCount);
            }
            else
            {
                byTarget[target] = (failures, ts, failures);
            }
        }

        var perTarget = byTarget
            .Select(kvp => new OutboundDependencyTarget(
                _redactor.Wrap(kvp.Key),
                kvp.Value.Failures,
                kvp.Value.PeakMinute))
            .OrderByDescending(t => t.Failures)
            .ToList();

        return new OutboundDependencyFailures(total, perTarget, peak);
    }

    private static DateTimeOffset AsDateTimeOffset(object? cell) => cell switch
    {
        DateTimeOffset dto => dto,
        DateTime dt => new DateTimeOffset(dt, TimeSpan.Zero),
        _ => DateTimeOffset.MinValue
    };
}
