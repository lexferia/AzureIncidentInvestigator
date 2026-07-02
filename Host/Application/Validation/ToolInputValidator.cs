using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using AzureIncidentInvestigator.Application.Charts;
using AzureIncidentInvestigator.Application.Options;
using AzureIncidentInvestigator.Domain.Charts;
using AzureIncidentInvestigator.Domain.Diagnostics;
using AzureIncidentInvestigator.Domain.Metrics;
using AzureIncidentInvestigator.Domain.Shared;

namespace AzureIncidentInvestigator.Application.Validation;

public sealed partial class ToolInputValidator
{
    [GeneratedRegex(@"^\d{1,20}:\d{1,20}$", RegexOptions.Compiled)]
    private static partial Regex IncidentIdRegex();

    [GeneratedRegex(@"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", RegexOptions.Compiled)]
    private static partial Regex ControlCharsRegex();

    private readonly AppServicePlansOptions _plans;
    private readonly AppServiceSitesOptions _sites;
    private readonly DatabasesOptions _dbs;
    private readonly AppInsightsOptions _ai;

    public ToolInputValidator(
        IOptions<AppServicePlansOptions> plans,
        IOptions<AppServiceSitesOptions> sites,
        IOptions<DatabasesOptions> dbs,
        IOptions<AppInsightsOptions> ai)
    {
        _plans = plans.Value;
        _sites = sites.Value;
        _dbs = dbs.Value;
        _ai = ai.Value;
    }

    public int ClampDays(int days) => Math.Clamp(days, 1, 30);
    public int ClampTop(int top) => Math.Clamp(top, 1, 100);

    public TimeWindow NormalizeWindow(DateTimeOffset? start, DateTimeOffset? end)
    {
        var endUtc = end ?? DateTimeOffset.UtcNow;
        var startUtc = start ?? endUtc.AddHours(-24);

        if (endUtc <= startUtc)
        {
            throw new ValidationException("window", "endTimeUtc must be after startTimeUtc.");
        }

        var maxWindow = TimeSpan.FromDays(_ai.MaxQueryWindowDays);
        if (endUtc - startUtc > maxWindow)
        {
            throw new ValidationException("window", $"Window must be {_ai.MaxQueryWindowDays} days or less.");
        }

        if (endUtc > DateTimeOffset.UtcNow.AddMinutes(1))
        {
            throw new ValidationException("window", "endTimeUtc cannot be in the future.");
        }

        return new TimeWindow(startUtc, endUtc);
    }

    public void ValidateIncidentId(string id)
    {
        if (string.IsNullOrEmpty(id) || !IncidentIdRegex().IsMatch(id))
        {
            throw new ValidationException(nameof(id), "incidentId must be in the form 'monitorId:logId'.");
        }
    }

    public void ValidatePlanResourceId(string resourceId)
    {
        if (!_plans.AllowedResourceIds.Contains(resourceId, StringComparer.OrdinalIgnoreCase))
        {
            throw new ValidationException(nameof(resourceId), "App Service Plan resource ID is not in the allowlist.");
        }
    }

    public void ValidateSiteResourceId(string resourceId)
    {
        if (!_sites.AllowedResourceIds.Contains(resourceId, StringComparer.OrdinalIgnoreCase))
        {
            throw new ValidationException(nameof(resourceId), "App Service Site resource ID is not in the allowlist.");
        }
    }

    public AllowedDatabase ValidateDatabaseKey(string key)
    {
        var match = _dbs.Allowed.FirstOrDefault(d => string.Equals(d.Key, key, StringComparison.OrdinalIgnoreCase));
        if (match is null)
        {
            throw new ValidationException(nameof(key), "Database key is not in the allowlist.");
        }
        return match;
    }

    public IReadOnlyList<DetectorKind> ValidateDetectorKinds(IReadOnlyList<string>? kinds)
    {
        if (kinds is null || kinds.Count == 0)
        {
            throw new ValidationException(nameof(kinds), "Provide at least one detector kind.");
        }
        if (kinds.Count > 12)
        {
            throw new ValidationException(nameof(kinds), "Max 12 detector kinds per call.");
        }
        var result = new List<DetectorKind>(kinds.Count);
        foreach (var raw in kinds)
        {
            if (!Enum.TryParse<DetectorKind>(raw, ignoreCase: true, out var parsed))
            {
                throw new ValidationException(
                    nameof(kinds),
                    $"Unknown detector kind '{raw}'. Valid: {string.Join(", ", Enum.GetNames<DetectorKind>())}");
            }
            if (!result.Contains(parsed))
            {
                result.Add(parsed);
            }
        }
        return result;
    }

    public IReadOnlyList<ValidatedChartSeries> ValidateChartSeries(IReadOnlyList<ChartSeriesInput>? series)
    {
        if (series is null || series.Count == 0)
        {
            throw new ValidationException(nameof(series), "Provide at least one chart series.");
        }
        if (series.Count > 4)
        {
            throw new ValidationException(nameof(series), "Max 4 chart series per call.");
        }

        var result = new List<ValidatedChartSeries>(series.Count);
        for (var i = 0; i < series.Count; i++)
        {
            var s = series[i];
            var prefix = $"series[{i}]";

            if (string.IsNullOrWhiteSpace(s.Label))
            {
                throw new ValidationException(prefix, "Series label is required.");
            }
            ValidateString(s.Label, $"{prefix}.label", maxLength: 64);

            if (!Enum.TryParse<ChartMetric>(s.Metric, ignoreCase: true, out var metric))
            {
                throw new ValidationException(
                    $"{prefix}.metric",
                    $"Unknown chart metric '{s.Metric}'. Valid: {string.Join(", ", Enum.GetNames<ChartMetric>())}");
            }

            if (!Enum.TryParse<MetricAggregation>(s.Aggregation, ignoreCase: true, out var agg))
            {
                throw new ValidationException(
                    $"{prefix}.aggregation",
                    $"Unknown aggregation '{s.Aggregation}'. Valid: Average, Maximum.");
            }

            string? planRid = null;
            AllowedDatabase? db = null;
            if (IsPlanMetric(metric))
            {
                if (string.IsNullOrWhiteSpace(s.AppServicePlanResourceId))
                {
                    throw new ValidationException($"{prefix}.appServicePlanResourceId", "Required for AppServicePlan* metrics.");
                }
                ValidatePlanResourceId(s.AppServicePlanResourceId);
                planRid = s.AppServicePlanResourceId;
            }
            else if (IsDatabaseMetric(metric))
            {
                if (string.IsNullOrWhiteSpace(s.DatabaseKey))
                {
                    throw new ValidationException($"{prefix}.databaseKey", "Required for Database* metrics.");
                }
                db = ValidateDatabaseKey(s.DatabaseKey);
            }
            // else: AppInsights derived series — no per-series target; workspace from config.

            result.Add(new ValidatedChartSeries(s.Label, metric, agg, planRid, db));
        }
        return result;
    }

    private static bool IsPlanMetric(ChartMetric m) => m switch
    {
        ChartMetric.AppServicePlanCpu or
        ChartMetric.AppServicePlanMemory or
        ChartMetric.AppServicePlanHttpQueue => true,
        _ => false
    };

    private static bool IsDatabaseMetric(ChartMetric m) => m switch
    {
        ChartMetric.DatabaseCpu or
        ChartMetric.DatabaseDtu or
        ChartMetric.DatabaseMemory or
        ChartMetric.DatabaseConnections => true,
        _ => false
    };

    public void ValidateString(string? value, string paramName, int maxLength = 256)
    {
        if (value is null)
        {
            return;
        }
        if (value.Length > maxLength)
        {
            throw new ValidationException(paramName, $"{paramName} exceeds {maxLength} characters.");
        }
        if (ControlCharsRegex().IsMatch(value))
        {
            throw new ValidationException(paramName, $"{paramName} contains control characters.");
        }
    }
}
