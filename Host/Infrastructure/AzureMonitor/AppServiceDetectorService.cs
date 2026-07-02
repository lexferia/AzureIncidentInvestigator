using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.Logging;
using AzureIncidentInvestigator.Application.Abstractions;
using AzureIncidentInvestigator.Application.Diagnostics;
using AzureIncidentInvestigator.Application.Errors;
using AzureIncidentInvestigator.Domain.Diagnostics;
using AzureIncidentInvestigator.Domain.Shared;
using AzureIncidentInvestigator.Infrastructure.AzureMonitor.Dtos;

namespace AzureIncidentInvestigator.Infrastructure.AzureMonitor;

public sealed class AppServiceDetectorService
{
    private const string ApiVersion = "2022-03-01";
    private const int MaxInsightsPerDetector = 20;

    private readonly HttpClient _http;
    private readonly ITextRedactor _redactor;
    private readonly ILogger<AppServiceDetectorService> _log;

    public AppServiceDetectorService(HttpClient http, ITextRedactor redactor, ILogger<AppServiceDetectorService> log)
    {
        _http = http;
        _redactor = redactor;
        _log = log;
    }

    public async Task<DetectorResult> QueryAsync(string allowedSiteResourceId, DetectorKind kind, TimeWindow window, CancellationToken ct)
    {
        var detectorName = DetectorKindMap.AzureName(kind);
        var siteSegment = allowedSiteResourceId.TrimStart('/');
        var startStr = window.StartUtc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
        var endStr = window.EndUtc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
        var path = $"{siteSegment}/detectors/{detectorName}?api-version={ApiVersion}&startTime={startStr}&endTime={endStr}";

        try
        {
            using var resp = await AzureAuthGuard.GuardAsync(() => _http.GetAsync(path, ct));
            if (resp.StatusCode == HttpStatusCode.NotFound)
            {
                return DetectorResult.Unavailable(kind, "Detector not available on this site/tier.");
            }
            if (!resp.IsSuccessStatusCode)
            {
                var body = await ReadErrorBodyAsync(resp, ct);
                _log.LogWarning("Detector {Detector} returned {Status}. Body: {Body}", detectorName, (int)resp.StatusCode, body);
                return DetectorResult.Unavailable(kind, $"Upstream {(int)resp.StatusCode}");
            }

            var dto = await resp.Content.ReadFromJsonAsync<DetectorResponseDto>(cancellationToken: ct);
            return Map(kind, dto);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (AuthenticationException)
        {
            // Auth failures are environment-level, not detector-specific — surface them to
            // the caller instead of masking every detector as "Unavailable".
            throw;
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Detector {Detector} threw; returning Unavailable", detectorName);
            return DetectorResult.Unavailable(kind, "Upstream error.");
        }
    }

    private static async Task<string> ReadErrorBodyAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        try
        {
            var body = await resp.Content.ReadAsStringAsync(ct);
            return body.Length > 1000 ? body[..1000] : body;
        }
        catch
        {
            return "<body unavailable>";
        }
    }

    private DetectorResult Map(DetectorKind kind, DetectorResponseDto? dto)
    {
        if (dto?.Properties is null)
        {
            return DetectorResult.Unavailable(kind, "Empty response.");
        }

        var status = MapStatus(dto.Properties.Status?.StatusId);
        var statusMsg = _redactor.Wrap(dto.Properties.Status?.Message ?? "");

        var insights = new List<DetectorInsight>();
        foreach (var ds in dto.Properties.Dataset ?? Enumerable.Empty<DetectorDatasetDto>())
        {
            if (insights.Count >= MaxInsightsPerDetector)
            {
                break;
            }
            var title = ds.RenderingProperties?.Title ?? "";
            var desc = ds.RenderingProperties?.Description ?? "";
            if (string.IsNullOrWhiteSpace(title) && string.IsNullOrWhiteSpace(desc))
            {
                continue;
            }
            insights.Add(new DetectorInsight(
                _redactor.Wrap(title),
                _redactor.Wrap(desc),
                ds.Table?.Rows?.Count ?? 0));
        }

        return new DetectorResult(kind, status, statusMsg, insights);
    }

    private static DetectorStatus MapStatus(int? statusId) => statusId switch
    {
        // Azure App Service Diagnostics statusId: 0=Critical, 1=Warning, 2=Info, 3=Success, 4=None
        0 => DetectorStatus.Critical,
        1 => DetectorStatus.Warning,
        2 => DetectorStatus.Info,
        3 => DetectorStatus.Healthy,
        _ => DetectorStatus.Info
    };
}
