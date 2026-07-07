using FluentAssertions;
using Xunit;

namespace AzureIncidentInvestigator;

public class SnatEvaluatorTests
{
    private static DetectorResult Detector(DetectorStatus status, string message = "", params string[] insightTitles) =>
        new(DetectorKind.SnatPortExhaustion, status, new SanitizedString(message),
            insightTitles.Select(t => new DetectorInsight(new SanitizedString(t), new SanitizedString(""), 0)).ToArray());

    [Fact]
    public void Critical_Exhausted()
    {
        SnatEvaluator.Evaluate(Detector(DetectorStatus.Critical, "SNAT ports exhausted"))
            .Verdict.Should().Be(SnatVerdict.Exhausted);
    }

    [Fact]
    public void Warning_Suspected()
    {
        SnatEvaluator.Evaluate(Detector(DetectorStatus.Warning))
            .Verdict.Should().Be(SnatVerdict.Suspected);
    }

    [Theory]
    [InlineData(DetectorStatus.Healthy)]
    [InlineData(DetectorStatus.Info)]
    public void HealthyOrInfo_NotExhausted(DetectorStatus status)
    {
        SnatEvaluator.Evaluate(Detector(status)).Verdict.Should().Be(SnatVerdict.NotExhausted);
    }

    [Fact]
    public void UnavailableDetector_UnknownWithFallbackMessage()
    {
        var finding = SnatEvaluator.Evaluate(DetectorResult.Unavailable(DetectorKind.SnatPortExhaustion, "tier"));
        finding.Verdict.Should().Be(SnatVerdict.Unknown);
        finding.Message.Should().Contain("NOT authoritative");
    }

    [Fact]
    public void NullDetector_Unknown()
    {
        SnatEvaluator.Evaluate(null).Verdict.Should().Be(SnatVerdict.Unknown);
    }

    // Regression for 2026-06-22: the SNAT detector was healthy (ports used well below allocated,
    // all SNAT connections successful). Regardless of any concurrent outbound dependency failures,
    // the SNAT verdict must be NotExhausted — the evaluator only ever consults the detector.
    [Fact]
    public void HealthyDetector_YieldsNotExhausted_RegardlessOfDependencyFailures()
    {
        var finding = SnatEvaluator.Evaluate(
            Detector(DetectorStatus.Healthy, "TCP ports Allocated 128, Used 20; all SNAT connections successful"));
        finding.Verdict.Should().Be(SnatVerdict.NotExhausted);
        finding.Source.Should().Be("AppServiceDiagnostics:snatportexhaustion");
    }
}
