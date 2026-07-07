
namespace AzureIncidentInvestigator;

public sealed record SuspiciousCrawler(
    SanitizedString UserAgent,
    string IpBucket,
    long RequestCount,
    UserAgentClass Classification,
    IReadOnlyList<CrawlerSignal> Signals,
    RiskScore Risk);
