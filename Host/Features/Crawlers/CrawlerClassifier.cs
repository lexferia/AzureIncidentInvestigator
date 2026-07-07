
namespace AzureIncidentInvestigator;

public sealed class CrawlerClassifier
{
    private static readonly string[] KnownBots =
    {
        "googlebot", "bingbot", "yandexbot", "duckduckbot", "baiduspider",
        "facebookexternalhit", "twitterbot", "slackbot", "linkedinbot",
        "applebot", "amazonbot"
    };

    private static readonly string[] AICrawlers =
    {
        "gptbot", "claudebot", "claude-web", "perplexitybot", "ccbot",
        "anthropic-ai", "openai", "chatgpt-user", "google-extended"
    };

    private static readonly string[] HeadlessMarkers =
    {
        "headlesschrome", "phantomjs", "puppeteer", "playwright", "selenium"
    };

    public SuspiciousCrawler Classify(CrawlerCandidate input)
    {
        var ua = input.UserAgent ?? string.Empty;
        var uaLower = ua.ToLowerInvariant();
        var signals = new List<CrawlerSignal>();
        var classification = UserAgentClass.Unknown;

        if (string.IsNullOrWhiteSpace(ua) || ua.Length < 8)
        {
            signals.Add(new CrawlerSignal("malformed-ua", 30, "user-agent missing or too short"));
            classification = UserAgentClass.Malformed;
        }
        else if (HeadlessMarkers.Any(m => uaLower.Contains(m, StringComparison.Ordinal)))
        {
            signals.Add(new CrawlerSignal("headless", 25, "headless browser marker detected"));
            classification = UserAgentClass.Headless;
        }
        else if (AICrawlers.Any(m => uaLower.Contains(m, StringComparison.Ordinal)))
        {
            signals.Add(new CrawlerSignal("ai-crawler", 15, "known AI-crawler user-agent"));
            classification = UserAgentClass.AICrawler;
        }
        else if (KnownBots.Any(m => uaLower.Contains(m, StringComparison.Ordinal)))
        {
            signals.Add(new CrawlerSignal("known-bot", 20, "well-known crawler user-agent"));
            classification = UserAgentClass.KnownBot;
        }
        else if (uaLower.Contains("mozilla", StringComparison.Ordinal))
        {
            classification = UserAgentClass.Browser;
        }

        if (input.RequestsPerHour > 1000)
        {
            signals.Add(new CrawlerSignal("high-rate", 20, $"{input.RequestsPerHour:F0} req/h"));
        }

        if (input.RequestCount > 0 && (double)input.NotFoundCount / input.RequestCount > 0.5)
        {
            signals.Add(new CrawlerSignal("high-404-ratio", 25, $"{input.NotFoundCount}/{input.RequestCount} 404s"));
        }

        if (input.RequestCount > 500 && (input.RequestsPerHour * (5.0 / 60.0)) > 500)
        {
            signals.Add(new CrawlerSignal("ip-burst", 20, $"{input.RequestCount} requests, sustained burst"));
        }

        var rawScore = signals.Sum(s => s.Weight);
        return new SuspiciousCrawler(
            new SanitizedString(ua.Length > 256 ? ua[..256] : ua),
            input.IpBucket,
            input.RequestCount,
            classification,
            signals,
            RiskScore.From(rawScore));
    }
}
