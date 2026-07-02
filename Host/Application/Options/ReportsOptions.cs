namespace AzureIncidentInvestigator.Application.Options;

public sealed class ReportsOptions
{
    public const string SectionName = "Reports";
    public string OutputDirectory { get; set; } = "%TEMP%\\AzureIncidentInvestigator\\reports";
    public List<string> KnownHosts { get; set; } = new();
}
