using AzureIncidentInvestigator.Application.Incidents;

namespace AzureIncidentInvestigator.Application.Abstractions;

public sealed record Report(string Markdown, DateTimeOffset GeneratedAtUtc, int RedactedItemsCount, string? FileSavedPath);

public interface IReportGenerationService
{
    Task<Report> BuildIncidentReportAsync(string incidentId, bool includeCrawlerAnalysis, bool saveToFile, CancellationToken ct);
    Task<IncidentAnalysis> AnalyzeIncidentAsync(string incidentId, bool includeCrawlerAnalysis, CancellationToken ct);
}
