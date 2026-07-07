using System.ComponentModel;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Server;

namespace AzureIncidentInvestigator;

[McpServerToolType]
public static class AppServiceHealthTools
{
    [McpServerTool(Name = "analyze_app_service_plan_health")]
    [Description("Analyze App Service Plan CPU, memory, and queue lengths for an allowlisted plan resource ID.")]
    public static Task<object> AnalyzePlan(
        AppServicePlanMetricsService svc,
        ToolInputValidator validator,
        ToolRateLimiter limiter,
        ILogger<ToolMarker> log,
        [Description("Resource ID of an App Service Plan in the configured allowlist.")] string appServicePlanResourceId,
        [Description("ISO-8601 UTC start. Optional; defaults to 24h before end.")] DateTimeOffset? startTimeUtc = null,
        [Description("ISO-8601 UTC end. Optional; defaults to now.")] DateTimeOffset? endTimeUtc = null,
        CancellationToken ct = default)
        => ToolExecution.RunAsync("analyze_app_service_plan_health", limiter, log, ct, async () =>
        {
            validator.ValidatePlanResourceId(appServicePlanResourceId);
            var window = validator.NormalizeWindow(startTimeUtc, endTimeUtc);
            return await svc.AnalyzeAsync(appServicePlanResourceId, window, ct);
        });

    [McpServerTool(Name = "analyze_app_service_site_health")]
    [Description("Analyze an App Service Site for an allowlisted site resource ID: restarts, an authoritative SNAT port-exhaustion verdict (from the Azure App Service SNAT Port Exhaustion detector — the same source as the portal), and — reported separately — failed outbound dependency calls (App Insights; NOT a SNAT signal).")]
    public static Task<object> AnalyzeSite(
        AppServiceSiteHealthService svc,
        ToolInputValidator validator,
        ToolRateLimiter limiter,
        ILogger<ToolMarker> log,
        [Description("Resource ID of an App Service Site in the configured allowlist.")] string appServiceSiteResourceId,
        [Description("ISO-8601 UTC start. Optional; defaults to 24h before end.")] DateTimeOffset? startTimeUtc = null,
        [Description("ISO-8601 UTC end. Optional; defaults to now.")] DateTimeOffset? endTimeUtc = null,
        CancellationToken ct = default)
        => ToolExecution.RunAsync("analyze_app_service_site_health", limiter, log, ct, async () =>
        {
            validator.ValidateSiteResourceId(appServiceSiteResourceId);
            var window = validator.NormalizeWindow(startTimeUtc, endTimeUtc);
            return await svc.AnalyzeAsync(appServiceSiteResourceId, window, ct);
        });
}
