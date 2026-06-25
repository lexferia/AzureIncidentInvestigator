using AzureIncidentInvestigator.Domain.Incidents;

namespace AzureIncidentInvestigator.Application.Abstractions;

public interface IIncidentService
{
    Task<IReadOnlyList<Incident>> GetRecentIncidentsAsync(int days, CancellationToken ct);
    Task<Incident?> GetIncidentByIdAsync(string incidentId, CancellationToken ct);
}
