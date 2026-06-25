using AzureIncidentInvestigator.Domain.Crawlers;
using AzureIncidentInvestigator.Domain.Shared;

namespace AzureIncidentInvestigator.Application.Abstractions;

public interface ICrawlerDetectionService
{
    Task<CrawlerAnalysis> DetectAsync(TimeWindow window, CancellationToken ct);
}
