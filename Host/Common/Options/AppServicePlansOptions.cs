namespace AzureIncidentInvestigator;

public sealed class AppServicePlansOptions
{
    public const string SectionName = "AppServicePlans";
    public List<string> AllowedResourceIds { get; set; } = new();
    public Dictionary<string, string> MonitorMappings { get; set; } = new();
    public int CpuWarnThreshold { get; set; } = 80;
    public int MemoryWarnThreshold { get; set; } = 80;
}
