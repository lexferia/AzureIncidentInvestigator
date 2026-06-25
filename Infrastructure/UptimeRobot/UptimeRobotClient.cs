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

    public async Task<IReadOnlyList<UptimeMonitor>> GetMonitorsAsync(CancellationToken ct)
    {
        var result = await _cache.GetOrCreateAsync("ur:monitors", async entry =>
        {
            entry.SlidingExpiration = TimeSpan.FromSeconds(_options.CurrentValue.CacheTtlSeconds);

            using var req = new HttpRequestMessage(HttpMethod.Post, "getMonitors")
            {
                Content = new FormUrlEncodedContent(Array.Empty<KeyValuePair<string, string>>())
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
                .Select(m => new UptimeMonitor(m.Id, m.FriendlyName ?? "", m.Url ?? "", (MonitorStatus)m.Status, m.Interval))
                .ToList();
        });

        return result ?? new List<UptimeMonitor>();
    }

    public async Task<IReadOnlyList<MonitorLog>> GetMonitorLogsAsync(long monitorId, DateTimeOffset from, DateTimeOffset to, CancellationToken ct)
    {
        var cacheKey = $"ur:logs:{monitorId}:{from:O}:{to:O}";
        var result = await _cache.GetOrCreateAsync(cacheKey, async entry =>
        {
            entry.SlidingExpiration = TimeSpan.FromSeconds(_options.CurrentValue.CacheTtlSeconds);

            var body = new StringBuilder();
            body.Append("monitors=").Append(monitorId);
            body.Append("&logs=1&logs_limit=100");
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

            var monitor = payload.Monitors?.FirstOrDefault();
            if (monitor?.Logs is null)
            {
                return new List<MonitorLog>();
            }

            return monitor.Logs.Select(l => new MonitorLog(
                monitorId,
                l.Id,
                l.Type,
                DateTimeOffset.FromUnixTimeSeconds(l.Datetime),
                l.Reason?.Detail,
                l.Duration)).ToList();
        });

        return result ?? new List<MonitorLog>();
    }
}
