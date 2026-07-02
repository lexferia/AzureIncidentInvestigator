using AzureIncidentInvestigator.Domain.Shared;

namespace AzureIncidentInvestigator.Domain.Crawlers;

public sealed record SuspiciousCrawler(
    SanitizedString UserAgent,
    string IpBucket,
    long RequestCount,
    UserAgentClass Classification,
    IReadOnlyList<CrawlerSignal> Signals,
    RiskScore Risk);
