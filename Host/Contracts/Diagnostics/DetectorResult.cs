
namespace AzureIncidentInvestigator;

public sealed record DetectorInsight(
    SanitizedString Title,
    SanitizedString Description,
    int DataRowCount);

public sealed record DetectorResult(
    DetectorKind Kind,
    DetectorStatus Status,
    SanitizedString StatusMessage,
    IReadOnlyList<DetectorInsight> Insights)
{
    public static DetectorResult Unavailable(DetectorKind kind, string reason) =>
        new(kind, DetectorStatus.Unavailable, new SanitizedString(reason), Array.Empty<DetectorInsight>());
}
