namespace AzureIncidentInvestigator;

public enum DetectorKind
{
    WebAppDown,
    WebAppSlow,
    HighCpu,
    MemoryAnalysis,
    WebAppRestarted,
    TcpConnections,
    ApplicationCrashes,
    Http4xxErrors,
    SnatPortExhaustion,
    SiteStartupFailures,
    HealthCheck
}
