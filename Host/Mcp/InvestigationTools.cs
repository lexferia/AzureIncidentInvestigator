// =============================================================================
// This file is the public attack surface of the MCP server.
//
// EVERY tool below is a SAFE, CONSTRAINED operation. The following capabilities
// are INTENTIONALLY ABSENT and must NEVER be added without a security review:
//
//   * run_kql / query_logs   — would defeat the parameterized-template guarantee
//   * fetch_url / http_get    — SSRF risk via a generic HTTP client
//   * execute_command         — game over for process confinement
//   * read_file / list_dir    — exfil channel
//   * get_config / get_env    — secret exposure
//   * any Azure ARM mutation  — this server is strictly read-only
//
// See docs/superpowers/specs/2026-05-26-azure-incident-investigator-design.md section 5.2
// =============================================================================

using System.ComponentModel;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace AzureIncidentInvestigator;

[McpServerToolType]
public static class InvestigationTools
{
    [McpServerTool(Name = "get_recent_downtime_incidents")]
    [Description("List recent downtime incidents from UptimeRobot (days clamped to 1-30).")]
    public static Task<object> GetRecentIncidents(
        IncidentService incidents,
        ToolInputValidator validator,
        ToolRateLimiter limiter,
        ILogger<ToolMarker> log,
        [Description("How many days back to look (1-30). Default 7.")] int days = 7,
        CancellationToken ct = default)
        => RunAsync("get_recent_downtime_incidents", limiter, log, ct, async () =>
        {
            var clampedDays = validator.ClampDays(days);
            var results = await incidents.GetRecentIncidentsAsync(clampedDays, ct);
            return new { incidents = results };
        });

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
        => RunAsync("analyze_incident", limiter, log, ct, async () =>
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

    [McpServerTool(Name = "detect_bad_crawlers")]
    [Description("Detect suspicious or abusive crawlers within a bounded time window (<= 7 days). Defaults to the last 24h.")]
    public static Task<object> DetectBadCrawlers(
        CrawlerDetectionService crawlers,
        ToolInputValidator validator,
        ToolRateLimiter limiter,
        ILogger<ToolMarker> log,
        [Description("ISO-8601 UTC start. Optional; defaults to 24h before end.")] DateTimeOffset? startTimeUtc = null,
        [Description("ISO-8601 UTC end. Optional; defaults to now.")] DateTimeOffset? endTimeUtc = null,
        CancellationToken ct = default)
        => RunAsync("detect_bad_crawlers", limiter, log, ct, async () =>
        {
            var window = validator.NormalizeWindow(startTimeUtc, endTimeUtc);
            return await crawlers.DetectAsync(window, ct);
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
        => RunAsync("generate_incident_report", limiter, log, ct, async () =>
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

    [McpServerTool(Name = "get_top_exceptions")]
    [Description("List top exception groups from Application Insights within a bounded time window.")]
    public static Task<object> GetTopExceptions(
        AppInsightsQueryService ai,
        ToolInputValidator validator,
        ToolRateLimiter limiter,
        ILogger<ToolMarker> log,
        [Description("ISO-8601 UTC start. Optional; defaults to 24h before end.")] DateTimeOffset? startTimeUtc = null,
        [Description("ISO-8601 UTC end. Optional; defaults to now.")] DateTimeOffset? endTimeUtc = null,
        [Description("Maximum items to return (1-100). Default 20.")] int top = 20,
        CancellationToken ct = default)
        => RunAsync("get_top_exceptions", limiter, log, ct, async () =>
        {
            var window = validator.NormalizeWindow(startTimeUtc, endTimeUtc);
            var clampedTop = validator.ClampTop(top);
            var result = await ai.GetTopExceptionsAsync(window, clampedTop, ct);
            return new { exceptions = result };
        });

    [McpServerTool(Name = "get_failed_dependencies")]
    [Description("List failed dependencies (external calls) from Application Insights within a bounded time window.")]
    public static Task<object> GetFailedDependencies(
        AppInsightsQueryService ai,
        ToolInputValidator validator,
        ToolRateLimiter limiter,
        ILogger<ToolMarker> log,
        [Description("ISO-8601 UTC start. Optional; defaults to 24h before end.")] DateTimeOffset? startTimeUtc = null,
        [Description("ISO-8601 UTC end. Optional; defaults to now.")] DateTimeOffset? endTimeUtc = null,
        [Description("Maximum items to return (1-100). Default 20.")] int top = 20,
        CancellationToken ct = default)
        => RunAsync("get_failed_dependencies", limiter, log, ct, async () =>
        {
            var window = validator.NormalizeWindow(startTimeUtc, endTimeUtc);
            var clampedTop = validator.ClampTop(top);
            var result = await ai.GetFailedDependenciesAsync(window, clampedTop, ct);
            return new { dependencies = result };
        });

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
        => RunAsync("analyze_app_service_plan_health", limiter, log, ct, async () =>
        {
            validator.ValidatePlanResourceId(appServicePlanResourceId);
            var window = validator.NormalizeWindow(startTimeUtc, endTimeUtc);
            return await svc.AnalyzeAsync(appServicePlanResourceId, window, ct);
        });

    [McpServerTool(Name = "analyze_app_service_site_health")]
    [Description("Analyze an App Service Site for restarts and SNAT-suspected outbound failures (heuristic) for an allowlisted site resource ID.")]
    public static Task<object> AnalyzeSite(
        AppServiceSiteHealthService svc,
        ToolInputValidator validator,
        ToolRateLimiter limiter,
        ILogger<ToolMarker> log,
        [Description("Resource ID of an App Service Site in the configured allowlist.")] string appServiceSiteResourceId,
        [Description("ISO-8601 UTC start. Optional; defaults to 24h before end.")] DateTimeOffset? startTimeUtc = null,
        [Description("ISO-8601 UTC end. Optional; defaults to now.")] DateTimeOffset? endTimeUtc = null,
        CancellationToken ct = default)
        => RunAsync("analyze_app_service_site_health", limiter, log, ct, async () =>
        {
            validator.ValidateSiteResourceId(appServiceSiteResourceId);
            var window = validator.NormalizeWindow(startTimeUtc, endTimeUtc);
            return await svc.AnalyzeAsync(appServiceSiteResourceId, window, ct);
        });

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
        => RunAsync("analyze_app_service_diagnostics", limiter, log, ct, async () =>
        {
            validator.ValidateSiteResourceId(appServiceSiteResourceId);
            var kinds = validator.ValidateDetectorKinds(detectorKinds);
            var window = validator.NormalizeWindow(startTimeUtc, endTimeUtc);

            var tasks = kinds.Select(k => svc.QueryAsync(appServiceSiteResourceId, k, window, ct)).ToArray();
            var results = await Task.WhenAll(tasks);
            return new { detectors = results };
        });

    [McpServerTool(Name = "analyze_database_health")]
    [Description("Analyze database health (CPU/DTU/memory/connections) for a database key configured in Databases:Allowed.")]
    public static Task<object> AnalyzeDatabase(
        DatabaseHealthService svc,
        ToolInputValidator validator,
        ToolRateLimiter limiter,
        ILogger<ToolMarker> log,
        [Description("Database key as configured in Databases:Allowed[].Key.")] string databaseKey,
        [Description("ISO-8601 UTC start. Optional; defaults to 24h before end.")] DateTimeOffset? startTimeUtc = null,
        [Description("ISO-8601 UTC end. Optional; defaults to now.")] DateTimeOffset? endTimeUtc = null,
        CancellationToken ct = default)
        => RunAsync("analyze_database_health", limiter, log, ct, async () =>
        {
            var allowed = validator.ValidateDatabaseKey(databaseKey);
            var window = validator.NormalizeWindow(startTimeUtc, endTimeUtc);
            return await svc.AnalyzeAsync(allowed, window, ct);
        });

    [McpServerTool(Name = "render_metric_chart")]
    [Description("Render a multi-series time-line chart (PNG, dark Azure-portal style) for App Service Plan and/or Database metrics. Returns the image inline plus a JSON metadata blob.")]
    public static Task<CallToolResult> RenderMetricChart(
        MetricChartService chart,
        ToolInputValidator validator,
        ToolRateLimiter limiter,
        ILogger<ToolMarker> log,
        [Description("1-4 series specs to overlay. Each series has Label, Metric (AppServicePlanCpu|AppServicePlanMemory|AppServicePlanHttpQueue|DatabaseCpu|DatabaseDtu|DatabaseMemory|DatabaseConnections|RequestsPerMinute|FailedRequestsPerMinute|ExceptionsPerMinute|SnatSuspectedFailuresPerMinute), and (for Plan/DB metrics only) either AppServicePlanResourceId (allowlisted) or DatabaseKey (allowlisted), plus Aggregation (Average|Maximum). App Insights time-series metrics don't require a per-series target.")] ChartSeriesSpec[] series,
        [Description("Optional chart title (<=256 chars; redacted before rendering).")] string? title = null,
        [Description("ISO-8601 UTC start. Optional; defaults to 24h before end.")] DateTimeOffset? startTimeUtc = null,
        [Description("ISO-8601 UTC end. Optional; defaults to now.")] DateTimeOffset? endTimeUtc = null,
        [Description("If true, also write the PNG to Reports:OutputDirectory.")] bool saveToFile = false,
        CancellationToken ct = default)
        => RunCallToolAsync("render_metric_chart", limiter, log, ct, async () =>
        {
            var inputs = (series ?? Array.Empty<ChartSeriesSpec>())
                .Select(s => new ChartSeriesInput(
                    s.Label,
                    s.Metric,
                    s.AppServicePlanResourceId,
                    s.DatabaseKey,
                    s.Aggregation))
                .ToList();

            var validated = validator.ValidateChartSeries(inputs);
            validator.ValidateString(title, "title", maxLength: 256);
            var window = validator.NormalizeWindow(startTimeUtc, endTimeUtc);

            var result = await chart.RenderAsync(title, validated, window, saveToFile, ct);

            var meta = new
            {
                seriesCount = result.SeriesCount,
                pointCount = result.TotalPointCount,
                savedPath = result.SavedPath
            };

            return new CallToolResult
            {
                Content =
                {
                    ImageContentBlock.FromBytes(result.Png, "image/png"),
                    new TextContentBlock { Text = JsonSerializer.Serialize(meta) }
                }
            };
        });

    private static async Task<object> RunAsync(
        string toolName,
        ToolRateLimiter limiter,
        ILogger log,
        CancellationToken ct,
        Func<Task<object>> body)
    {
        var correlationId = Guid.NewGuid().ToString("N");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            if (!await limiter.TryAcquireAsync(toolName, ct))
            {
                log.LogWarning("Rate limited {Tool} {CorrelationId}", toolName, correlationId);
                return new { error = "rate_limited", tool = toolName };
            }

            var result = await body();
            log.LogInformation("tool.invoked {Tool} {CorrelationId} duration={Duration}ms outcome=ok",
                toolName, correlationId, sw.ElapsedMilliseconds);
            return result;
        }
        catch (ValidationException vex)
        {
            log.LogWarning("tool.invoked {Tool} {CorrelationId} duration={Duration}ms outcome=validation param={Param}",
                toolName, correlationId, sw.ElapsedMilliseconds, vex.ParameterName);
            return new { error = "validation", parameter = vex.ParameterName, message = vex.Message };
        }
        catch (ConfigurationException cex)
        {
            log.LogWarning("tool.invoked {Tool} {CorrelationId} duration={Duration}ms outcome=configuration setting={Setting}",
                toolName, correlationId, sw.ElapsedMilliseconds, cex.Setting);
            return new { error = "configuration", setting = cex.Setting, message = cex.Message, retryable = false };
        }
        catch (AuthenticationException aex)
        {
            log.LogWarning(aex, "tool.invoked {Tool} {CorrelationId} duration={Duration}ms outcome=authentication",
                toolName, correlationId, sw.ElapsedMilliseconds);
            return new { error = "authentication", message = aex.Message, retryable = false };
        }
        catch (OperationCanceledException)
        {
            log.LogInformation("tool.invoked {Tool} {CorrelationId} duration={Duration}ms outcome=cancelled",
                toolName, correlationId, sw.ElapsedMilliseconds);
            return new { error = "cancelled" };
        }
        catch (Exception ex)
        {
            log.LogError(ex, "tool.invoked {Tool} {CorrelationId} duration={Duration}ms outcome=upstream",
                toolName, correlationId, sw.ElapsedMilliseconds);
            return new { error = "upstream", message = "An upstream error occurred. See server logs." };
        }
    }

    private static async Task<CallToolResult> RunCallToolAsync(
        string toolName,
        ToolRateLimiter limiter,
        ILogger log,
        CancellationToken ct,
        Func<Task<CallToolResult>> body)
    {
        var correlationId = Guid.NewGuid().ToString("N");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            if (!await limiter.TryAcquireAsync(toolName, ct))
            {
                log.LogWarning("Rate limited {Tool} {CorrelationId}", toolName, correlationId);
                return ErrorResult($"{{\"error\":\"rate_limited\",\"tool\":\"{toolName}\"}}");
            }

            var result = await body();
            log.LogInformation("tool.invoked {Tool} {CorrelationId} duration={Duration}ms outcome=ok",
                toolName, correlationId, sw.ElapsedMilliseconds);
            return result;
        }
        catch (ValidationException vex)
        {
            log.LogWarning("tool.invoked {Tool} {CorrelationId} duration={Duration}ms outcome=validation param={Param}",
                toolName, correlationId, sw.ElapsedMilliseconds, vex.ParameterName);
            var payload = JsonSerializer.Serialize(new { error = "validation", parameter = vex.ParameterName, message = vex.Message });
            return ErrorResult(payload);
        }
        catch (ConfigurationException cex)
        {
            log.LogWarning("tool.invoked {Tool} {CorrelationId} duration={Duration}ms outcome=configuration setting={Setting}",
                toolName, correlationId, sw.ElapsedMilliseconds, cex.Setting);
            var payload = JsonSerializer.Serialize(new { error = "configuration", setting = cex.Setting, message = cex.Message, retryable = false });
            return ErrorResult(payload);
        }
        catch (AuthenticationException aex)
        {
            log.LogWarning(aex, "tool.invoked {Tool} {CorrelationId} duration={Duration}ms outcome=authentication",
                toolName, correlationId, sw.ElapsedMilliseconds);
            var payload = JsonSerializer.Serialize(new { error = "authentication", message = aex.Message, retryable = false });
            return ErrorResult(payload);
        }
        catch (OperationCanceledException)
        {
            log.LogInformation("tool.invoked {Tool} {CorrelationId} duration={Duration}ms outcome=cancelled",
                toolName, correlationId, sw.ElapsedMilliseconds);
            return ErrorResult("{\"error\":\"cancelled\"}");
        }
        catch (Exception ex)
        {
            log.LogError(ex, "tool.invoked {Tool} {CorrelationId} duration={Duration}ms outcome=upstream",
                toolName, correlationId, sw.ElapsedMilliseconds);
            return ErrorResult("{\"error\":\"upstream\",\"message\":\"An upstream error occurred. See server logs.\"}");
        }
    }

    private static CallToolResult ErrorResult(string jsonPayload) => new()
    {
        IsError = true,
        Content = { new TextContentBlock { Text = jsonPayload } }
    };

    /// <summary>Logger category marker for tool invocations.</summary>
    public sealed class ToolMarker;
}
