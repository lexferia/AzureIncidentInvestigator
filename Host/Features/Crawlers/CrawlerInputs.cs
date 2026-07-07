namespace AzureIncidentInvestigator;

public sealed record CrawlerCandidate(
    string UserAgent,
    string IpBucket,
    long RequestCount,
    long NotFoundCount,
    double RequestsPerHour);
