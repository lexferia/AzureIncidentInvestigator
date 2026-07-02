namespace AzureIncidentInvestigator.Domain.Crawlers;

public sealed record CrawlerAnalysis(
    DateTimeOffset GeneratedAtUtc,
    IReadOnlyList<SuspiciousCrawler> Crawlers,
    int TotalEvaluated,
    int SuspiciousCount);
