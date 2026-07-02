using Azure;
using Azure.Monitor.Query;
using Azure.Monitor.Query.Models;
using Microsoft.Extensions.Options;
using AzureIncidentInvestigator.Application.Abstractions;
using AzureIncidentInvestigator.Application.Options;
using AzureIncidentInvestigator.Application.Queries;
using AzureIncidentInvestigator.Domain.Metrics;
using AzureIncidentInvestigator.Domain.Shared;

namespace AzureIncidentInvestigator.Infrastructure.AzureMonitor;

internal sealed class AppServiceSiteHealthService : IAppServiceSiteHealthService
{
    private readonly LogsQueryClient _client;
    private readonly IOptionsMonitor<AppInsightsOptions> _options;
    private readonly ITextRedactor _redactor;

    public AppServiceSiteHealthService(LogsQueryClient client, IOptionsMonitor<AppInsightsOptions> options, ITextRedactor redactor)
    {
        _client = client;
        _options = options;
        _redactor = redactor;
    }

    public async Task<AppServiceSiteHealth> AnalyzeAsync(string allowedSiteResourceId, TimeWindow window, CancellationToken ct)
    {
        var restartsTask = GetRestartsAsync(allowedSiteResourceId, window, ct);
        var snatTask = GetSnatExhaustionSignalsAsync(window, ct);
        await Task.WhenAll(restartsTask, snatTask);
        return new AppServiceSiteHealth(allowedSiteResourceId, await restartsTask, await snatTask);
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

    public async Task<SnatExhaustionFinding> GetSnatExhaustionSignalsAsync(TimeWindow window, CancellationToken ct)
    {
        var workspaceId = _options.CurrentValue.WorkspaceId;
        if (string.IsNullOrWhiteSpace(workspaceId))
        {
            return new SnatExhaustionFinding(false, 0, Array.Empty<SnatTargetFailure>(), null);
        }

        Response<LogsQueryResult> response = await AzureAuthGuard.GuardAsync(() => _client.QueryWorkspaceAsync(
            workspaceId,
            KqlTemplate.SnatSuspectFailures,
            new QueryTimeRange(window.StartUtc, window.EndUtc),
            cancellationToken: ct));

        var rows = response.Value.Table.Rows;
        if (rows.Count == 0)
        {
            return new SnatExhaustionFinding(false, 0, Array.Empty<SnatTargetFailure>(), null);
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
            .Select(kvp => new SnatTargetFailure(
                _redactor.Wrap(kvp.Key),
                kvp.Value.Failures,
                kvp.Value.PeakMinute))
            .OrderByDescending(t => t.Failures)
            .ToList();

        return new SnatExhaustionFinding(true, total, perTarget, peak);
    }

    private static DateTimeOffset AsDateTimeOffset(object? cell) => cell switch
    {
        DateTimeOffset dto => dto,
        DateTime dt => new DateTimeOffset(dt, TimeSpan.Zero),
        _ => DateTimeOffset.MinValue
    };
}
