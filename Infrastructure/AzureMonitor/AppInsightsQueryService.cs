using Azure;
using Azure.Monitor.Query;
using Azure.Monitor.Query.Models;
using Microsoft.Extensions.Options;
using AzureIncidentInvestigator.Application.Abstractions;
using AzureIncidentInvestigator.Application.Options;
using AzureIncidentInvestigator.Application.Queries;
using AzureIncidentInvestigator.Domain.Crawlers;
using AzureIncidentInvestigator.Domain.Metrics;
using AzureIncidentInvestigator.Domain.Shared;
using AzureIncidentInvestigator.Domain.Telemetry;

namespace AzureIncidentInvestigator.Infrastructure.AzureMonitor;

internal sealed class AppInsightsQueryService : IAppInsightsQueryService
{
    private readonly LogsQueryClient _client;
    private readonly IOptionsMonitor<AppInsightsOptions> _options;
    private readonly ITextRedactor _redactor;

    public AppInsightsQueryService(LogsQueryClient client, IOptionsMonitor<AppInsightsOptions> options, ITextRedactor redactor)
    {
        _client = client;
        _options = options;
        _redactor = redactor;
    }

    private static QueryTimeRange Range(TimeWindow w) => new(w.StartUtc, w.EndUtc);

    private async Task<LogsTable> RunAsync(string kql, TimeWindow window, CancellationToken ct)
    {
        var workspaceId = _options.CurrentValue.WorkspaceId;
        if (string.IsNullOrWhiteSpace(workspaceId))
        {
            throw new InvalidOperationException("AppInsights:WorkspaceId is not configured.");
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(_options.CurrentValue.QueryTimeoutSeconds));

        Response<LogsQueryResult> response = await _client.QueryWorkspaceAsync(
            workspaceId,
            kql,
            Range(window),
            cancellationToken: cts.Token);

        return response.Value.Table;
    }

    public async Task<IReadOnlyList<ExceptionGroup>> GetTopExceptionsAsync(TimeWindow w, int top, CancellationToken ct)
    {
        var table = await RunAsync(KqlTemplate.TopExceptions(top), w, ct);
        var result = new List<ExceptionGroup>(table.Rows.Count);
        foreach (var row in table.Rows)
        {
            result.Add(new ExceptionGroup(
                _redactor.Wrap(row[0]?.ToString() ?? ""),
                _redactor.Wrap(row[1]?.ToString() ?? ""),
                Convert.ToInt64(row[2]),
                AsDateTimeOffset(row[3]),
                AsDateTimeOffset(row[4]),
                ParseSet(row[5]).Select(_redactor.Wrap).ToList()));
        }
        return result;
    }

    public async Task<IReadOnlyList<RequestFailure>> GetFailedRequestsAsync(TimeWindow w, int top, CancellationToken ct)
    {
        var table = await RunAsync(KqlTemplate.FailedRequests(top), w, ct);
        return table.Rows.Select(row => new RequestFailure(
            _redactor.Wrap(row[0]?.ToString() ?? ""),
            Convert.ToInt64(row[1]),
            ParseSet(row[2]).Select(_redactor.Wrap).ToList(),
            Convert.ToDouble(row[3]))).ToList();
    }

    public async Task<IReadOnlyList<DependencyFailure>> GetFailedDependenciesAsync(TimeWindow w, int top, CancellationToken ct)
    {
        var table = await RunAsync(KqlTemplate.FailedDependencies(top), w, ct);
        return table.Rows.Select(row => new DependencyFailure(
            _redactor.Wrap(row[0]?.ToString() ?? ""),
            _redactor.Wrap(row[1]?.ToString() ?? ""),
            Convert.ToInt64(row[2]),
            Convert.ToDouble(row[3]),
            ParseSet(row[4]).Select(_redactor.Wrap).ToList())).ToList();
    }

    public async Task<IReadOnlyList<UserAgentRollup>> GetTopUserAgentsAsync(TimeWindow w, int top, CancellationToken ct)
    {
        var uaExpr = CompileColumn(c => c.UserAgent);
        var table = await RunAsync(KqlTemplate.TopUserAgents(top, uaExpr), w, ct);
        return table.Rows.Select(row => new UserAgentRollup(
            row[0]?.ToString() ?? "",
            Convert.ToInt64(row[1]),
            Convert.ToInt64(row[2]))).ToList();
    }

    public async Task<IReadOnlyList<IpRollup>> GetTopClientIpsAsync(TimeWindow w, int top, CancellationToken ct)
    {
        var ipExpr = CompileColumn(c => c.ClientIp);
        var table = await RunAsync(KqlTemplate.TopClientIps(top, ipExpr), w, ct);
        return table.Rows.Select(row => new IpRollup(
            row[0]?.ToString() ?? "",
            Convert.ToInt64(row[1]))).ToList();
    }

    private string CompileColumn(Func<TelemetryColumnOptions, List<string>> picker)
    {
        var cols = _options.CurrentValue.TelemetryColumns ?? new TelemetryColumnOptions();
        return TelemetryColumnExpression.Compile(picker(cols));
    }

    public async Task<IReadOnlyList<BurstyCrawlerEvent>> GetBurstyCrawlerActivityAsync(TimeWindow w, int minRequestsPerBin, CancellationToken ct)
    {
        var ipExpr = CompileColumn(c => c.ClientIp);
        var uaExpr = CompileColumn(c => c.UserAgent);
        var countryExpr = CompileColumn(c => c.Country);
        var table = await RunAsync(KqlTemplate.BurstyCrawlerActivity(minRequestsPerBin, ipExpr, uaExpr, countryExpr), w, ct);
        var result = new List<BurstyCrawlerEvent>(table.Rows.Count);
        foreach (var row in table.Rows)
        {
            // Columns from KQL: bin(timestamp,10m), ClientIp, client_CountryOrRegion, UserAgent, RequestCount
            result.Add(new BurstyCrawlerEvent(
                AsDateTimeOffset(row[0]),
                _redactor.Wrap(row[1]?.ToString() ?? ""),
                _redactor.Wrap(row[2]?.ToString() ?? ""),
                _redactor.Wrap(row[3]?.ToString() ?? ""),
                Convert.ToInt64(row[4])));
        }
        return result;
    }

    public async Task<MetricSeries> GetTimeSeriesAsync(AppInsightsSeriesKind kind, TimeWindow w, CancellationToken ct)
    {
        var grain = PickGrainMinutes(w);
        var kql = kind switch
        {
            AppInsightsSeriesKind.Requests => KqlTemplate.RequestsPerBin(grain),
            AppInsightsSeriesKind.FailedRequests => KqlTemplate.FailedRequestsPerBin(grain),
            AppInsightsSeriesKind.Exceptions => KqlTemplate.ExceptionsPerBin(grain),
            AppInsightsSeriesKind.SnatSuspectedFailures => KqlTemplate.SnatSuspectFailuresPerBin(grain),
            _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown series kind.")
        };

        var table = await RunAsync(kql, w, ct);
        var points = new List<MetricPoint>(table.Rows.Count);
        foreach (var row in table.Rows)
        {
            // Columns: bin(timestamp, Nm), Value
            points.Add(new MetricPoint(AsDateTimeOffset(row[0]), Convert.ToDouble(row[1])));
        }
        return new MetricSeries(kind.ToString(), "count", points);
    }

    private static int PickGrainMinutes(TimeWindow w)
    {
        var hours = w.Duration.TotalHours;
        return hours switch
        {
            <= 6 => 1,
            <= 24 => 5,
            <= 72 => 15,
            _ => 60
        };
    }

    public async Task<IReadOnlyDictionary<string, long>> GetStatusCodeBreakdownAsync(TimeWindow w, CancellationToken ct)
    {
        var table = await RunAsync(KqlTemplate.StatusCodeBreakdown, w, ct);
        var dict = new Dictionary<string, long>();
        foreach (var row in table.Rows)
        {
            dict[row[0]?.ToString() ?? "unknown"] = Convert.ToInt64(row[1]);
        }
        return dict;
    }

    private static DateTimeOffset AsDateTimeOffset(object? cell) => cell switch
    {
        DateTimeOffset dto => dto,
        DateTime dt => new DateTimeOffset(dt, TimeSpan.Zero),
        _ => DateTimeOffset.MinValue
    };

    private static IEnumerable<string> ParseSet(object? cell)
    {
        if (cell is null)
        {
            return Array.Empty<string>();
        }
        if (cell is IEnumerable<object> en)
        {
            return en.Select(o => o?.ToString() ?? "").Where(s => s.Length > 0);
        }
        var s = cell.ToString();
        if (string.IsNullOrEmpty(s))
        {
            return Array.Empty<string>();
        }
        return s.Trim('[', ']').Split(',').Select(x => x.Trim().Trim('"')).Where(x => x.Length > 0);
    }
}
