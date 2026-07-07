namespace AzureIncidentInvestigator;

/// <summary>
/// Turns the authoritative Azure App Service "SNAT Port Exhaustion" detector result into a
/// <see cref="SnatFinding"/>. This is the ONLY source of the SNAT verdict — outbound dependency
/// failures (App Insights) are deliberately NOT considered here, because failure volume to a
/// host does not imply SNAT port exhaustion.
/// </summary>
public static class SnatEvaluator
{
    public const string Source = "AppServiceDiagnostics:snatportexhaustion";

    public const string UnavailableMessage =
        "SNAT port metrics unavailable; falling back to dependency-failure signal, which is NOT authoritative.";

    public static SnatFinding Evaluate(DetectorResult? snatDetector)
    {
        if (snatDetector is null || snatDetector.Status == DetectorStatus.Unavailable)
        {
            return new SnatFinding(SnatVerdict.Unknown, Source, UnavailableMessage, Array.Empty<SanitizedString>());
        }

        var verdict = snatDetector.Status switch
        {
            DetectorStatus.Critical => SnatVerdict.Exhausted,
            DetectorStatus.Warning => SnatVerdict.Suspected,
            _ => SnatVerdict.NotExhausted // Healthy / Info: ports below allocated, no failed SNAT connections
        };

        var evidence = new List<SanitizedString>();
        if (!string.IsNullOrWhiteSpace(snatDetector.StatusMessage.Value))
        {
            evidence.Add(snatDetector.StatusMessage);
        }
        foreach (var insight in snatDetector.Insights)
        {
            evidence.Add(insight.Title);
            if (!string.IsNullOrWhiteSpace(insight.Description.Value))
            {
                evidence.Add(insight.Description);
            }
        }

        var message = verdict == SnatVerdict.NotExhausted
            ? "App Service SNAT Port Exhaustion detector reports no exhaustion for this window."
            : null;

        return new SnatFinding(verdict, Source, message, evidence);
    }
}
