using System.Globalization;

namespace AzureIncidentInvestigator.Application.Queries;

/// <summary>
/// KQL templates. Time ranges are passed via LogsQueryClient.QueryTimeRange (SDK-bound).
/// The only template parameter is `top`, which is always an int clamped to [1, 100]
/// by ToolInputValidator. Integer substitution into KQL is safe because the type is
/// constrained — strings are never substituted via these helpers.
/// </summary>
internal static class KqlTemplate
{
    private const string TopExceptionsRaw = """
        exceptions
        | summarize Count = count(),
                    FirstSeen = min(timestamp),
                    LastSeen = max(timestamp),
                    Operations = make_set(operation_Name, 10)
                    by Type = type, Message = tostring(outerMessage)
        | top {TOP} by Count desc
        """;

    private const string FailedRequestsRaw = """
        requests
        | where success == false
        | summarize Count = count(),
                    ResultCodes = make_set(tostring(resultCode), 10),
                    AvgDuration = avg(duration)
                    by Name = name
        | top {TOP} by Count desc
        """;

    private const string FailedDependenciesRaw = """
        dependencies
        | where success == false
        | summarize Count = count(),
                    AvgDuration = avg(duration),
                    ResultCodes = make_set(tostring(resultCode), 10)
                    by Target = target, Type = type
        | top {TOP} by Count desc
        """;

    private const string TopUserAgentsRaw = """
        requests
        | extend ua = {USER_AGENT_EXPR}
        | where isnotempty(ua)
        | summarize Total = count(),
                    NotFound = countif(tostring(resultCode) == "404")
                    by UserAgent = ua
        | top {TOP} by Total desc
        """;

    private const string TopClientIpsRaw = """
        requests
        | extend ip = {CLIENT_IP_EXPR}
        | where isnotempty(ip)
        | extend bucket = strcat(split(ip,".")[0],".",split(ip,".")[1],".",split(ip,".")[2],".0/24")
        | summarize Total = count() by Bucket = bucket
        | top {TOP} by Total desc
        """;

    public const string StatusCodeBreakdown = """
        requests
        | summarize Count = count() by StatusCode = tostring(resultCode)
        """;

    public const string AppServiceRestarts = """
        AppServicePlatformLogs
        | where OperationName in ("Application stopped", "Application started", "RecycleApp", "Application is shutting down")
        | project TimeGenerated, OperationName, Description = tostring(ResultDescription)
        | order by TimeGenerated asc
        """;

    public const string SnatSuspectFailures = """
        dependencies
        | where success == false
        | where type in ("Http", "HTTP", "Https")
        | where (resultCode in ("0","-1","408","504")) or duration > 30000
        | summarize Failures = count() by bin(timestamp, 1m), Target = target
        | where Failures > 5
        | order by timestamp asc
        """;

    private const string BurstyCrawlerActivityRaw = """
        requests
        | extend ClientIp = {CLIENT_IP_EXPR}
        | extend UserAgent = {USER_AGENT_EXPR}
        | extend Country = {COUNTRY_EXPR}
        | summarize RequestCount = count()
            by bin(timestamp, 10m), ClientIp, Country, UserAgent
        | where RequestCount > {MIN}
        | order by timestamp desc
        """;

    // Per-minute time-series for charting. Parameter is bin grain in minutes (1, 5, 15, 60).
    private const string RequestsPerBinRaw = """
        requests
        | summarize Value = count() by bin(timestamp, {GRAIN}m)
        | order by timestamp asc
        """;

    private const string FailedRequestsPerBinRaw = """
        requests
        | where success == false
        | summarize Value = count() by bin(timestamp, {GRAIN}m)
        | order by timestamp asc
        """;

    private const string ExceptionsPerBinRaw = """
        exceptions
        | summarize Value = count() by bin(timestamp, {GRAIN}m)
        | order by timestamp asc
        """;

    private const string SnatSuspectFailuresPerBinRaw = """
        dependencies
        | where success == false
        | where type in ("Http", "HTTP", "Https")
        | where (resultCode in ("0","-1","408","504")) or duration > 30000
        | summarize Value = count() by bin(timestamp, {GRAIN}m)
        | order by timestamp asc
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
