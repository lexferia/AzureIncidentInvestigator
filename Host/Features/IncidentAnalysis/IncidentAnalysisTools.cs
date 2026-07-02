using System.ComponentModel;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Server;

namespace AzureIncidentInvestigator;

[McpServerToolType]
public static class IncidentAnalysisTools
{
    [McpServerTool(Name = "analyze_incident")]
    [Description("Analyze an incident: correlate with exceptions, dependencies, crawlers, App Service Plan/Site health, and Database health.")]
    public static Task<object> AnalyzeIncident(
        ReportGenerationService reports,
        ToolInputValidator validator,
        ToolRateLimiter limiter,
        ILogger<ToolMarker> log,
        [Description("Incident id in the form '<monitorId>:<logId>'.")] string incidentId,
        [Description("Whether to include crawler analysis. Default true.")] bool includeCrawlerAnalysis = true,
        CancellationToken ct = default)
        => ToolExecution.RunAsync("analyze_incident", limiter, log, ct, async () =>
        {
            validator.ValidateIncidentId(incidentId);
            var analysis = await reports.AnalyzeIncidentAsync(incidentId, includeCrawlerAnalysis, ct);
            return new
            {
                summary = analysis.Summary.Value,
                topExceptions = analysis.TopExceptions,
                failedDependencies = analysis.FailedDependencies,
                suspiciousCrawlers = analysis.SuspiciousCrawlers,
                appServicePlanHealth = analysis.AppServicePlanHealth,
                appServiceSiteHealth = analysis.AppServiceSiteHealth,
                databaseHealth = analysis.DatabaseHealth,
                appServiceDiagnostics = analysis.AppServiceDiagnostics,
                possibleRootCauses = analysis.PossibleRootCauses,
                redactedItemsCount = analysis.RedactedItemsCount
            };
        });

    [McpServerTool(Name = "generate_incident_report")]
    [Description("Generate a markdown investigation report for an incident. Optionally write it to the configured reports directory.")]
    public static Task<object> GenerateIncidentReport(
        ReportGenerationService reports,
        ToolInputValidator validator,
        ToolRateLimiter limiter,
        ILogger<ToolMarker> log,
        [Description("Incident id in the form '<monitorId>:<logId>'.")] string incidentId,
        [Description("Whether to include crawler analysis. Default true.")] bool includeCrawlerAnalysis = true,
        [Description("If true, write the report markdown to the configured Reports:OutputDirectory.")] bool saveToFile = false,
        CancellationToken ct = default)
        => ToolExecution.RunAsync("generate_incident_report", limiter, log, ct, async () =>
        {
            validator.ValidateIncidentId(incidentId);
            var report = await reports.BuildIncidentReportAsync(incidentId, includeCrawlerAnalysis, saveToFile, ct);
            return new
            {
                markdown = report.Markdown,
                fileSavedPath = report.FileSavedPath,
                redactedItemsCount = report.RedactedItemsCount
            };
        });
}
