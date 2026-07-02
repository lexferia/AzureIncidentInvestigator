using AzureIncidentInvestigator.Domain.Shared;

namespace AzureIncidentInvestigator.Domain.Crawlers;

/// <summary>
/// One time-bucketed (IP, country, UA) request burst exceeding the configured threshold.
/// Produced by KqlTemplate.BurstyCrawlerActivity.
/// </summary>
public sealed record BurstyCrawlerEvent(
    DateTimeOffset BucketStartUtc,
    SanitizedString ClientIp,
    SanitizedString Country,
    SanitizedString UserAgent,
    long RequestCount);
