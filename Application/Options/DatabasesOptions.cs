using AzureIncidentInvestigator.Domain.Metrics;

namespace AzureIncidentInvestigator.Application.Options;

public sealed class AllowedDatabase
{
    public string Key { get; set; } = string.Empty;
    public DatabaseType Type { get; set; }
    public string ResourceId { get; set; } = string.Empty;
}

public sealed class DatabasesOptions
{
    public const string SectionName = "Databases";
    public List<AllowedDatabase> Allowed { get; set; } = new();
    public int CpuWarnThreshold { get; set; } = 75;
    public int ConnectionFailWarnPerMinute { get; set; } = 10;
    public Dictionary<string, List<string>> MonitorMappings { get; set; } = new();
}
