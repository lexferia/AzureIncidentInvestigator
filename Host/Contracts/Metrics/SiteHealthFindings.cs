namespace AzureIncidentInvestigator;

/// <summary>
/// Authoritative SNAT port-exhaustion verdict, derived from the Azure App Service
/// Diagnostics "SNAT Port Exhaustion" detector (the same source the portal renders) —
/// NOT from App Insights outbound-dependency failures.
/// </summary>
public enum SnatVerdict
{
    /// <summary>Detector reports healthy: ports used well below allocated, no failed SNAT connections.</summary>
    NotExhausted,
    /// <summary>Detector warns SNAT usage is approaching limits.</summary>
    Suspected,
    /// <summary>Detector reports SNAT port exhaustion (failed/pending SNAT connections).</summary>
    Exhausted,
    /// <summary>Platform SNAT metrics were unavailable; no authoritative verdict could be made.</summary>
    Unknown
}

public sealed record SnatFinding(
    SnatVerdict Verdict,
    string Source,
    string? Message,
    IReadOnlyList<SanitizedString> Evidence);

/// <summary>
/// Failed outbound dependency calls (App Insights AppDependencies). This is an
/// application-level signal and is NOT authoritative for SNAT port exhaustion — high
/// failure volume to one host usually means a slow/erroring backend, not SNAT.
/// </summary>
public sealed record OutboundDependencyTarget(SanitizedString Target, long Failures, DateTimeOffset PeakMinuteUtc);

public sealed record OutboundDependencyFailures(
    long TotalFailures,
    IReadOnlyList<OutboundDependencyTarget> ByTarget,
    DateTimeOffset? PeakMinuteUtc);
