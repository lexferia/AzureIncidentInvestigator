using AzureIncidentInvestigator.Domain.Diagnostics;
using AzureIncidentInvestigator.Domain.Shared;

namespace AzureIncidentInvestigator.Application.Abstractions;

public interface IAppServiceDetectorService
{
    Task<DetectorResult> QueryAsync(string allowedSiteResourceId, DetectorKind kind, TimeWindow window, CancellationToken ct);
}
