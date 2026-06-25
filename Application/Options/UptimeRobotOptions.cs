namespace AzureIncidentInvestigator.Application.Options;

public sealed class UptimeRobotOptions
{
    public const string SectionName = "UptimeRobot";
    public string BaseUrl { get; set; } = "https://api.uptimerobot.com/v2/";
    public string ApiKey { get; set; } = string.Empty;
    public int TimeoutSeconds { get; set; } = 10;
    public int CacheTtlSeconds { get; set; } = 60;
}
