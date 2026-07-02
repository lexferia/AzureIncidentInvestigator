using System.Globalization;

namespace AzureIncidentInvestigator.Application.Queries;

/// <summary>
/// KQL templates. Time ranges are passed via LogsQueryClient.QueryTimeRange (SDK-bound).
/// The only template parameter is `top`, which is always an int clamped to [1, 100]
/// by ToolInputValidator. Integer substitution into KQL is safe because the type is
/// constrained — strings are never substituted via these helpers.
///
/// These target the WORKSPACE-BASED Application Insights schema (AppRequests /
/// AppDependencies / AppExceptions, with TimeGenerated/DurationMs/PascalCase columns),
/// because the server queries a Log Analytics workspace via QueryWorkspaceAsync. The
/// legacy classic table names (requests/dependencies/exceptions) do NOT resolve there.
/// </summary>
internal static class KqlTemplate
{
    private const string TopExceptionsRaw = """
        AppExceptions
        | summarize Count = count(),
                    FirstSeen = min(TimeGenerated),
                    LastSeen = max(TimeGenerated),
                    Operations = make_set(OperationName, 10)
                    by Type = ExceptionType, Message = tostring(OuterMessage)
        | top {TOP} by Count desc
        """;

    private const string FailedRequestsRaw = """
        AppRequests
        | where Success == false
        | summarize Count = count(),
                    ResultCodes = make_set(tostring(ResultCode), 10),
                    AvgDuration = avg(DurationMs)
                    by Name = Name
        | top {TOP} by Count desc
        """;

    private const string FailedDependenciesRaw = """
        AppDependencies
        | where Success == false
        | summarize Count = count(),
                    AvgDuration = avg(DurationMs),
                    ResultCodes = make_set(tostring(ResultCode), 10)
                    by Target = Target, Type = DependencyType
        | top {TOP} by Count desc
        """;

    private const string TopUserAgentsRaw = """
        AppRequests
        | extend ua = {USER_AGENT_EXPR}
        | where isnotempty(ua)
        | summarize Total = count(),
                    NotFound = countif(tostring(ResultCode) == "404")
                    by UserAgent = ua
        | top {TOP} by Total desc
        """;

    private const string TopClientIpsRaw = """
        AppRequests
        | extend ip = {CLIENT_IP_EXPR}
        | where isnotempty(ip)
        | extend bucket = strcat(split(ip,".")[0],".",split(ip,".")[1],".",split(ip,".")[2],".0/24")
        | summarize Total = count() by Bucket = bucket
        | top {TOP} by Total desc
        """;

    public const string StatusCodeBreakdown = """
        AppRequests
        | summarize Count = count() by StatusCode = tostring(ResultCode)
        """;

    public const string AppServiceRestarts = """
        AppServicePlatformLogs
        | where OperationName in ("Application stopped", "Application started", "RecycleApp", "Application is shutting down")
        | project TimeGenerated, OperationName, Description = tostring(Message)
        | order by TimeGenerated asc
        """;

    public const string SnatSuspectFailures = """
        AppDependencies
        | where Success == false
        | where DependencyType in ("Http", "HTTP", "Https")
        | where (ResultCode in ("0","-1","408","504")) or DurationMs > 30000
        | summarize Failures = count() by bin(TimeGenerated, 1m), Target = Target
        | where Failures > 5
        | order by TimeGenerated asc
        """;

    private const string BurstyCrawlerActivityRaw = """
        AppRequests
        | extend ClientIp = {CLIENT_IP_EXPR}
        | extend UserAgent = {USER_AGENT_EXPR}
        | extend Country = {COUNTRY_EXPR}
        | summarize RequestCount = count()
            by bin(TimeGenerated, 10m), ClientIp, Country, UserAgent
        | where RequestCount > {MIN}
        | order by TimeGenerated desc
        """;

    // Per-minute time-series for charting. Parameter is bin grain in minutes (1, 5, 15, 60).
    private const string RequestsPerBinRaw = """
        AppRequests
        | summarize Value = count() by bin(TimeGenerated, {GRAIN}m)
        | order by TimeGenerated asc
        """;

    private const string FailedRequestsPerBinRaw = """
        AppRequests
        | where Success == false
        | summarize Value = count() by bin(TimeGenerated, {GRAIN}m)
        | order by TimeGenerated asc
        """;

    private const string ExceptionsPerBinRaw = """
        AppExceptions
        | summarize Value = count() by bin(TimeGenerated, {GRAIN}m)
        | order by TimeGenerated asc
        """;

    private const string SnatSuspectFailuresPerBinRaw = """
        AppDependencies
        | where Success == false
        | where DependencyType in ("Http", "HTTP", "Https")
        | where (ResultCode in ("0","-1","408","504")) or DurationMs > 30000
        | summarize Value = count() by bin(TimeGenerated, {GRAIN}m)
        | order by TimeGenerated asc
        """;

    public static string TopExceptions(int top) => BindTop(TopExceptionsRaw, top);
    public static string FailedRequests(int top) => BindTop(FailedRequestsRaw, top);
    public static string FailedDependencies(int top) => BindTop(FailedDependenciesRaw, top);

    public static string TopUserAgents(int top, string userAgentExpr) =>
        BindTop(TopUserAgentsRaw, top).Replace("{USER_AGENT_EXPR}", userAgentExpr, StringComparison.Ordinal);

    public static string TopClientIps(int top, string clientIpExpr) =>
        BindTop(TopClientIpsRaw, top).Replace("{CLIENT_IP_EXPR}", clientIpExpr, StringComparison.Ordinal);

    public static string BurstyCrawlerActivity(int minRequestsPerBin, string clientIpExpr, string userAgentExpr, string countryExpr) =>
        BurstyCrawlerActivityRaw
            .Replace("{MIN}", Math.Clamp(minRequestsPerBin, 1, 100_000).ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal)
            .Replace("{CLIENT_IP_EXPR}", clientIpExpr, StringComparison.Ordinal)
            .Replace("{USER_AGENT_EXPR}", userAgentExpr, StringComparison.Ordinal)
            .Replace("{COUNTRY_EXPR}", countryExpr, StringComparison.Ordinal);

    public static string RequestsPerBin(int grainMinutes) => BindGrain(RequestsPerBinRaw, grainMinutes);
    public static string FailedRequestsPerBin(int grainMinutes) => BindGrain(FailedRequestsPerBinRaw, grainMinutes);
    public static string ExceptionsPerBin(int grainMinutes) => BindGrain(ExceptionsPerBinRaw, grainMinutes);
    public static string SnatSuspectFailuresPerBin(int grainMinutes) => BindGrain(SnatSuspectFailuresPerBinRaw, grainMinutes);

    private static string BindTop(string template, int top)
    {
        // top is clamped to [1, 100] upstream by ToolInputValidator.
        var clamped = Math.Clamp(top, 1, 100);
        return template.Replace("{TOP}", clamped.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal);
    }

    private static string BindGrain(string template, int grainMinutes)
    {
        // grainMinutes is clamped to a small set: 1, 5, 15, 60.
        var clamped = grainMinutes switch
        {
            <= 1 => 1,
            <= 5 => 5,
            <= 15 => 15,
            _ => 60
        };
        return template.Replace("{GRAIN}", clamped.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal);
    }
}
