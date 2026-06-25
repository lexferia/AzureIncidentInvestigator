using FluentAssertions;
using Microsoft.Extensions.Options;
using AzureIncidentInvestigator.Application.Options;
using AzureIncidentInvestigator.Application.Validation;
using AzureIncidentInvestigator.Domain.Metrics;
using Xunit;

namespace AzureIncidentInvestigator.Tests.Application;

public class ToolInputValidatorTests
{
    private static ToolInputValidator NewValidator(
        AppServicePlansOptions? plans = null,
        AppServiceSitesOptions? sites = null,
        DatabasesOptions? dbs = null,
        AppInsightsOptions? ai = null) =>
        new(
            Options.Create(plans ?? new AppServicePlansOptions()),
            Options.Create(sites ?? new AppServiceSitesOptions()),
            Options.Create(dbs ?? new DatabasesOptions()),
            Options.Create(ai ?? new AppInsightsOptions()));

    [Theory]
    [InlineData(0, 1)]
    [InlineData(-5, 1)]
    [InlineData(60, 30)]
    [InlineData(7, 7)]
    public void ClampDays_ReturnsExpected(int input, int expected)
    {
        NewValidator().ClampDays(input).Should().Be(expected);
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(200, 100)]
    [InlineData(20, 20)]
    public void ClampTop_ReturnsExpected(int input, int expected)
    {
        NewValidator().ClampTop(input).Should().Be(expected);
    }

    [Fact]
    public void NormalizeWindow_WhenBothNull_Defaults24h()
    {
        var w = NewValidator().NormalizeWindow(null, null);
        (w.EndUtc - w.StartUtc).Should().BeCloseTo(TimeSpan.FromHours(24), TimeSpan.FromSeconds(1));
    }

    [Fact]
    public void NormalizeWindow_WhenEndBeforeStart_Throws()
    {
        var v = NewValidator();
        var act = () => v.NormalizeWindow(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(-1));
        act.Should().Throw<ValidationException>();
    }

    [Fact]
    public void NormalizeWindow_WhenWindowExceedsMax_Throws()
    {
        var v = NewValidator(ai: new AppInsightsOptions { MaxQueryWindowDays = 7 });
        var start = DateTimeOffset.UtcNow.AddDays(-10);
        var end = DateTimeOffset.UtcNow;
        var act = () => v.NormalizeWindow(start, end);
        act.Should().Throw<ValidationException>();
    }

    [Theory]
    [InlineData("123:456")]
    [InlineData("9:9")]
    public void ValidateIncidentId_Accepts(string id) => NewValidator().ValidateIncidentId(id);

    [Theory]
    [InlineData("")]
    [InlineData("abc:def")]
    [InlineData("12345-67890")]
    [InlineData(":1")]
    public void ValidateIncidentId_Rejects(string id)
    {
        var act = () => NewValidator().ValidateIncidentId(id);
        act.Should().Throw<ValidationException>();
    }

    [Fact]
    public void ValidatePlanResourceId_WhenNotAllowed_Throws()
    {
        var v = NewValidator(plans: new AppServicePlansOptions { AllowedResourceIds = { "/allowed" } });
        var act = () => v.ValidatePlanResourceId("/not-allowed");
        act.Should().Throw<ValidationException>();
    }

    [Fact]
    public void ValidatePlanResourceId_WhenAllowed_Passes()
    {
        var v = NewValidator(plans: new AppServicePlansOptions { AllowedResourceIds = { "/allowed" } });
        v.ValidatePlanResourceId("/allowed");
    }

    [Fact]
    public void ValidateDatabaseKey_WhenAllowed_ReturnsEntry()
    {
        var v = NewValidator(dbs: new DatabasesOptions
        {
            Allowed = { new AllowedDatabase { Key = "prod-db", ResourceId = "/r", Type = DatabaseType.SqlDatabase } }
        });
        v.ValidateDatabaseKey("prod-db").Key.Should().Be("prod-db");
    }

    [Fact]
    public void ValidateDatabaseKey_WhenUnknown_Throws()
    {
        var v = NewValidator(dbs: new DatabasesOptions());
        var act = () => v.ValidateDatabaseKey("unknown");
        act.Should().Throw<ValidationException>();
    }
}
