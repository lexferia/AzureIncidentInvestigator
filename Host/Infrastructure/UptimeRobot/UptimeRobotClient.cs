using System.Net.Http.Json;
using System.Text;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using AzureIncidentInvestigator.Application.Abstractions;
using AzureIncidentInvestigator.Application.Options;
using AzureIncidentInvestigator.Domain.Incidents;
using AzureIncidentInvestigator.Infrastructure.UptimeRobot.Dtos;

namespace AzureIncidentInvestigator.Infrastructure.UptimeRobot;

internal sealed class UptimeRobotClient : IUptimeRobotClient
{
    private readonly HttpClient _http;
    private readonly IMemoryCache _cache;
    private readonly IOptionsMonitor<UptimeRobotOptions> _options;

    public UptimeRobotClient(HttpClient http, IMemoryCache cache, IOptionsMonitor<UptimeRobotOptions> options)
    {
        _http = http;
        _cache = cache;
        _options = options;
    }

    public async Task<IReadOnlyList<MonitorWithLogs>> GetMonitorsWithLogsAsync(DateTimeOffset from, DateTimeOffset to, CancellationToken ct)
    {
        var cacheKey = $"ur:monitorswithlogs:{from:O}:{to:O}";
        var result = await _cache.GetOrCreateAsync(cacheKey, async entry =>
        {
            entry.SlidingExpiration = TimeSpan.FromSeconds(_options.CurrentValue.CacheTtlSeconds);

            // One request for ALL monitors and their logs. logs=1 makes UptimeRobot embed
            // each monitor's downtime logs in the same getMonitors response, so we avoid a
            // per-monitor call storm that trips the API's 429 rate limit.
            var body = new StringBuilder();
            body.Append("logs=1&logs_limit=100");
            body.Append("&logs_start_date=").Append(from.ToUnixTimeSeconds());
            body.Append("&logs_end_date=").Append(to.ToUnixTimeSeconds());

            using var req = new HttpRequestMessage(HttpMethod.Post, "getMonitors")
            {
                Content = new StringContent(body.ToString(), Encoding.UTF8, "application/x-www-form-urlencoded")
            };

            using var resp = await _http.SendAsync(req, ct);
            resp.EnsureSuccessStatusCode();
            var payload = await resp.Content.ReadFromJsonAsync<GetMonitorsResponse>(cancellationToken: ct)
                          ?? throw new InvalidOperationException("Empty UptimeRobot response.");

            if (!string.Equals(payload.Stat, "ok", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException($"UptimeRobot error: {payload.Error?.Message ?? "unknown"}");
            }

            return (payload.Monitors ?? new List<MonitorDto>())
                .Select(m => new MonitorWithLogs(
                    new UptimeMonitor(m.Id, m.FriendlyName ?? "", m.Url ?? "", (MonitorStatus)m.Status, m.Interval),
                    (m.Logs ?? new List<LogDto>())
                        .Select(l => new MonitorLog(
                            m.Id,
                            l.Id,
                            l.Type,
                            DateTimeOffset.FromUnixTimeSeconds(l.Datetime),
                            l.Reason?.Detail,
                            l.Duration))
                        .ToList()))
                .ToList();
        });

        return result ?? new List<MonitorWithLogs>();
    }
}
