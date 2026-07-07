
namespace AzureIncidentInvestigator;

public sealed class CrawlerDetectionService
{
    // Default burst threshold per 10-minute bin. >150 in any single bin from the same
    // (IP, UA) tuple is treated as a candidate worth classifying.
    private const int DefaultBurstThreshold = 150;

    // 10-minute bins; multiply by 6 to project max-burst-per-bin to a per-hour rate
    // for the classifier's high-rate signal.
    private const double BinsPerHour = 6.0;

    private readonly AppInsightsQueryService _ai;
    private readonly CrawlerClassifier _classifier;

    public CrawlerDetectionService(AppInsightsQueryService ai, CrawlerClassifier classifier)
    {
        _ai = ai;
        _classifier = classifier;
    }

    public async Task<CrawlerAnalysis> DetectAsync(TimeWindow window, CancellationToken ct)
    {
        var bursty = await _ai.GetBurstyCrawlerActivityAsync(window, DefaultBurstThreshold, ct);

        // Group bursty events by (UA, IP) so multiple bins for the same culprit collapse to one candidate.
        var grouped = bursty
            .GroupBy(e => (UA: e.UserAgent.Value, IP: e.ClientIp.Value), StringTupleComparer.Instance)
            .Select(g => new
            {
                UserAgent = g.Key.UA,
                IpBucket = ToIpBucket(g.Key.IP),
                Country = g.First().Country.Value,
                TotalRequests = g.Sum(x => x.RequestCount),
                BinsObserved = g.LongCount(),
                MaxPerBin = g.Max(x => x.RequestCount)
            })
            .OrderByDescending(g => g.TotalRequests)
            .Take(50)
            .ToList();

        var crawlers = new List<SuspiciousCrawler>(grouped.Count);
        foreach (var g in grouped)
        {
            var ratePerHour = g.MaxPerBin * BinsPerHour;
            var notFoundCount = 0L; // KqlTemplate.BurstyCrawlerActivity does not project status codes.

            var candidate = new CrawlerCandidate(g.UserAgent, g.IpBucket, g.TotalRequests, notFoundCount, ratePerHour);
            crawlers.Add(_classifier.Classify(candidate));
        }

        var suspicious = crawlers
            .Where(c => c.Risk.Bucket == RiskBucket.Suspicious)
            .ToList();

        return new CrawlerAnalysis(DateTimeOffset.UtcNow, suspicious, crawlers.Count, suspicious.Count);
    }

    /// <summary>
    /// Mask the last octet of an IPv4 address to a /24 bucket. Pass-through for IPv6 or malformed input.
    /// </summary>
    private static string ToIpBucket(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip))
        {
            return "unknown";
        }
        var parts = ip.Split('.');
        if (parts.Length != 4)
        {
            return ip;
        }
        return $"{parts[0]}.{parts[1]}.{parts[2]}.0/24";
    }

    private sealed class StringTupleComparer : IEqualityComparer<(string UA, string IP)>
    {
        public static readonly StringTupleComparer Instance = new();
        public bool Equals((string UA, string IP) x, (string UA, string IP) y) =>
            string.Equals(x.UA, y.UA, StringComparison.Ordinal) &&
            string.Equals(x.IP, y.IP, StringComparison.Ordinal);
        public int GetHashCode((string UA, string IP) obj) =>
            HashCode.Combine(obj.UA, obj.IP);
    }
}
