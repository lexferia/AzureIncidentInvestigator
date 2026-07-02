namespace AzureIncidentInvestigator.Application.Crawlers;

public sealed record CrawlerCandidate(
    string UserAgent,
    string IpBucket,
    long RequestCount,
    long NotFoundCount,
    double RequestsPerHour);
