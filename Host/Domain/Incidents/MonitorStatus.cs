namespace AzureIncidentInvestigator.Domain.Incidents;

public enum MonitorStatus
{
    Unknown = 0,
    Paused = 1,
    NotCheckedYet = 2,
    Up = 3,
    SeemsDown = 4,
    Down = 5
}
