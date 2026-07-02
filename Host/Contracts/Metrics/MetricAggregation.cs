namespace AzureIncidentInvestigator;

public enum MetricAggregation
{
    Average = 0,
    Maximum = 1
}

public enum PlanMetricSeriesKind
{
    Cpu = 0,
    Memory = 1,
    HttpQueue = 2,
    DiskQueue = 3
}

public enum DatabaseMetricSeriesKind
{
    Cpu = 0,
    Dtu = 1,
    Memory = 2,
    Connections = 3
}
