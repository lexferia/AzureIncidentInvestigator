namespace AzureIncidentInvestigator.Application.Options;

public sealed class AppInsightsOptions
{
    public const string SectionName = "AppInsights";
    public string WorkspaceId { get; set; } = string.Empty;
    public int MaxQueryWindowDays { get; set; } = 7;
    public int QueryTimeoutSeconds { get; set; } = 20;

    /// <summary>
    /// How this workspace stores the client IP, user-agent, and country on `requests`.
    /// Each entry is "&lt;source&gt;:&lt;key&gt;" where source is "customDimensions" or "builtIn".
    /// Lists form a coalesce fallback chain. Defaults try the user's customDimensions
    /// keys first, then fall back to the App Insights built-in columns.
    /// </summary>
    public TelemetryColumnOptions TelemetryColumns { get; set; } = new();
}

public sealed class TelemetryColumnOptions
{
    public List<string> ClientIp { get; set; } = new()
    {
        "customDimensions:Client IP Address",
        "builtIn:ClientIP"
    };

    public List<string> UserAgent { get; set; } = new()
    {
        "customDimensions:User-Agent"
    };

    public List<string> Country { get; set; } = new()
    {
        "builtIn:ClientCountryOrRegion"
    };
}
