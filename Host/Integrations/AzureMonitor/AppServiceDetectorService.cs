using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.Logging;

namespace AzureIncidentInvestigator;

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

        var datasets = dto.Properties.Dataset ?? Enumerable.Empty<DetectorDatasetDto>();

        var insights = new List<DetectorInsight>();
        foreach (var ds in datasets)
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

        // Portal fidelity: App Service colors the detector tile from the worst status across
        // its Insights rows, not only the top-level status (which is often Info/None). Take the
        // most severe of the top-level status and any per-insight "Status" cells.
        var topStatus = MapStatus(dto.Properties.Status?.StatusId);
        var effectiveStatus = (dto.Properties.Dataset ?? new List<DetectorDatasetDto>())
            .SelectMany(InsightStatuses)
            .Append(topStatus)
            .Where(s => s != DetectorStatus.Unavailable)
            .DefaultIfEmpty(topStatus)
            .Max();

        var statusMsg = _redactor.Wrap(dto.Properties.Status?.Message ?? "");
        return new DetectorResult(kind, effectiveStatus, statusMsg, insights);
    }

    // Reads per-row severities from an "Insights"-style dataset (a table with a "Status" column).
    private static IEnumerable<DetectorStatus> InsightStatuses(DetectorDatasetDto ds)
    {
        var columns = ds.Table?.Columns;
        var rows = ds.Table?.Rows;
        if (columns is null || rows is null)
        {
            yield break;
        }
        var statusIdx = columns.FindIndex(c => string.Equals(c.ColumnName, "Status", StringComparison.OrdinalIgnoreCase));
        if (statusIdx < 0)
        {
            yield break;
        }
        foreach (var row in rows)
        {
            if (statusIdx < row.Count && ParseInsightStatus(row[statusIdx]) is { } parsed)
            {
                yield return parsed;
            }
        }
    }

    private static DetectorStatus? ParseInsightStatus(object? cell)
    {
        var s = cell?.ToString();
        if (string.IsNullOrWhiteSpace(s))
        {
            return null;
        }
        // App Service insight status is either the numeric enum (0=Critical..3=Success) or its name.
        if (int.TryParse(s, out var n))
        {
            return MapStatus(n);
        }
        return s.Trim().ToLowerInvariant() switch
        {
            "critical" or "error" => DetectorStatus.Critical,
            "warning" => DetectorStatus.Warning,
            "info" => DetectorStatus.Info,
            "success" or "healthy" or "none" => DetectorStatus.Healthy,
            _ => null
        };
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
