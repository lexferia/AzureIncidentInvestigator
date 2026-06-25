using System.Collections.Concurrent;
using System.Threading.RateLimiting;
using Microsoft.Extensions.Options;
using AzureIncidentInvestigator.Application.Options;

namespace AzureIncidentInvestigator.Host.RateLimiting;

public sealed class ToolRateLimiter : IDisposable
{
    private readonly ConcurrentDictionary<string, RateLimiter> _limiters = new();
    private readonly IOptionsMonitor<RateLimitOptions> _options;

    public ToolRateLimiter(IOptionsMonitor<RateLimitOptions> options) => _options = options;

    public async ValueTask<bool> TryAcquireAsync(string toolName, CancellationToken ct)
    {
        var limiter = _limiters.GetOrAdd(toolName, _ =>
            new TokenBucketRateLimiter(new TokenBucketRateLimiterOptions
            {
                TokenLimit = _options.CurrentValue.PerToolPerMinute,
                TokensPerPeriod = _options.CurrentValue.PerToolPerMinute,
                ReplenishmentPeriod = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true
            }));

        using var lease = await limiter.AcquireAsync(1, ct);
        return lease.IsAcquired;
    }

    public void Dispose()
    {
        foreach (var l in _limiters.Values)
        {
            l.Dispose();
        }
        _limiters.Clear();
    }
}
