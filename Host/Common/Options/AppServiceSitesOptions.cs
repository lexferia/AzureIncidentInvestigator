namespace AzureIncidentInvestigator;

public sealed class AppServiceSitesOptions
{
    public const string SectionName = "AppServiceSites";
    public List<string> AllowedResourceIds { get; set; } = new();
    public Dictionary<string, string> MonitorMappings { get; set; } = new();
}
