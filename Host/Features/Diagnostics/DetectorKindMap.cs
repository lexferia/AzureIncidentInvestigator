
namespace AzureIncidentInvestigator;

/// <summary>
/// Maps the allowlisted DetectorKind enum to the Azure App Service Diagnostics detector slug.
/// The Azure side is case-insensitive; slugs chosen to match the portal's "Availability and Performance" panel.
/// </summary>
internal static class DetectorKindMap
{
    public static string AzureName(DetectorKind kind) => kind switch
    {
        DetectorKind.WebAppDown => "webappdown",
        DetectorKind.WebAppSlow => "webappperformance",
        DetectorKind.HighCpu => "AppPerformanceCPUAnalysis",
        DetectorKind.MemoryAnalysis => "memoryanalysis",
        DetectorKind.WebAppRestarted => "apprestartanalysis",
        DetectorKind.TcpConnections => "tcpconnections",
        DetectorKind.ApplicationCrashes => "applicationcrashes",
        DetectorKind.Http4xxErrors => "http4xx",
        DetectorKind.SnatPortExhaustion => "snatportexhaustion",
        DetectorKind.SiteStartupFailures => "sitestartupfailures",
        DetectorKind.HealthCheck => "healthcheck",
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown DetectorKind.")
    };
}
