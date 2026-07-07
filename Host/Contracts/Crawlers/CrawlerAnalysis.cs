namespace AzureIncidentInvestigator;

public sealed record CrawlerAnalysis(
    DateTimeOffset GeneratedAtUtc,
    IReadOnlyList<SuspiciousCrawler> Crawlers,
    int TotalEvaluated,
    int SuspiciousCount);
