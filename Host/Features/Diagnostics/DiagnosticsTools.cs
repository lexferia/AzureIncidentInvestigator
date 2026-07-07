using System.ComponentModel;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Server;

namespace AzureIncidentInvestigator;

[McpServerToolType]
public static class DiagnosticsTools
{
    [McpServerTool(Name = "analyze_app_service_diagnostics")]
    [Description("Query Azure App Service Diagnostics detectors (SnatPortExhaustion, WebAppRestarted, HighCpu, etc.) for an allowlisted site. More authoritative than App-Insights heuristics.")]
    public static Task<object> AnalyzeAppServiceDiagnostics(
        AppServiceDetectorService svc,
        ToolInputValidator validator,
        ToolRateLimiter limiter,
        ILogger<ToolMarker> log,
        [Description("Resource ID of an App Service Site in the configured allowlist.")] string appServiceSiteResourceId,
        [Description("Detector kinds to query. Valid: WebAppDown, WebAppSlow, HighCpu, MemoryAnalysis, WebAppRestarted, TcpConnections, ApplicationCrashes, Http4xxErrors, SnatPortExhaustion, SiteStartupFailures, HealthCheck.")] string[] detectorKinds,
        [Description("ISO-8601 UTC start. Optional; defaults to 24h before end.")] DateTimeOffset? startTimeUtc = null,
        [Description("ISO-8601 UTC end. Optional; defaults to now.")] DateTimeOffset? endTimeUtc = null,
        CancellationToken ct = default)
        => ToolExecution.RunAsync("analyze_app_service_diagnostics", limiter, log, ct, async () =>
        {
            validator.ValidateSiteResourceId(appServiceSiteResourceId);
            var kinds = validator.ValidateDetectorKinds(detectorKinds);
            var window = validator.NormalizeWindow(startTimeUtc, endTimeUtc);

            var tasks = kinds.Select(k => svc.QueryAsync(appServiceSiteResourceId, k, window, ct)).ToArray();
            var results = await Task.WhenAll(tasks);
            return new { detectors = results };
        });
}
