namespace AzureIncidentInvestigator.Application.Options;

public sealed class RateLimitOptions
{
    public const string SectionName = "RateLimits";
    public int PerToolPerMinute { get; set; } = 30;
}
