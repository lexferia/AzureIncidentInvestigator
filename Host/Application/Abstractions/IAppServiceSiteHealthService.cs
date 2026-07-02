using AzureIncidentInvestigator.Domain.Metrics;
using AzureIncidentInvestigator.Domain.Shared;

namespace AzureIncidentInvestigator.Application.Abstractions;

public interface IAppServiceSiteHealthService
{
    Task<AppServiceSiteHealth> AnalyzeAsync(string allowedSiteResourceId, TimeWindow window, CancellationToken ct);
    Task<IReadOnlyList<RestartEvent>> GetRestartsAsync(string allowedSiteResourceId, TimeWindow window, CancellationToken ct);
    Task<SnatExhaustionFinding> GetSnatExhaustionSignalsAsync(TimeWindow window, CancellationToken ct);
}
