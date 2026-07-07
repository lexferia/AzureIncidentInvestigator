using FluentAssertions;
using Microsoft.Extensions.Options;
using Xunit;

namespace AzureIncidentInvestigator;

public class DetectorValidationTests
{
    private static ToolInputValidator NewValidator() => new(
        Options.Create(new AppServicePlansOptions()),
        Options.Create(new AppServiceSitesOptions()),
        Options.Create(new DatabasesOptions()),
        Options.Create(new AppInsightsOptions()));

    [Fact]
    public void ValidateDetectorKinds_AcceptsKnownNames_CaseInsensitive()
    {
        var v = NewValidator();
        var result = v.ValidateDetectorKinds(new[] { "snatportexhaustion", "WebAppRestarted", "HIGHCPU" });
        result.Should().HaveCount(3)
            .And.Contain(DetectorKind.SnatPortExhaustion)
            .And.Contain(DetectorKind.WebAppRestarted)
            .And.Contain(DetectorKind.HighCpu);
    }

    [Fact]
    public void ValidateDetectorKinds_Dedupes()
    {
        var v = NewValidator();
        v.ValidateDetectorKinds(new[] { "HighCpu", "highcpu" }).Should().HaveCount(1);
    }

    [Fact]
    public void ValidateDetectorKinds_RejectsUnknown()
    {
        var v = NewValidator();
        var act = () => v.ValidateDetectorKinds(new[] { "RandomDetector" });
        act.Should().Throw<ValidationException>();
    }

    [Fact]
    public void ValidateDetectorKinds_RejectsEmpty()
    {
        var v = NewValidator();
        var act = () => v.ValidateDetectorKinds(Array.Empty<string>());
        act.Should().Throw<ValidationException>();
    }

    [Fact]
    public void ValidateDetectorKinds_RejectsNull()
    {
        var v = NewValidator();
        var act = () => v.ValidateDetectorKinds(null);
        act.Should().Throw<ValidationException>();
    }

    [Fact]
    public void ValidateDetectorKinds_RejectsTooMany()
    {
        var v = NewValidator();
        var act = () => v.ValidateDetectorKinds(Enumerable.Repeat("HighCpu", 13).ToArray());
        act.Should().Throw<ValidationException>();
    }

    [Fact]
    public void DetectorKindMap_AllEnumValuesHaveMapping()
    {
        foreach (var kind in Enum.GetValues<DetectorKind>())
        {
            DetectorKindMap.AzureName(kind).Should().NotBeNullOrWhiteSpace($"kind {kind} must map to an Azure detector slug");
        }
    }
}
