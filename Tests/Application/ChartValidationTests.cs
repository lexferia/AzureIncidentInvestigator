using FluentAssertions;
using Microsoft.Extensions.Options;
using Xunit;

namespace AzureIncidentInvestigator;

public class ChartValidationTests
{
    private const string PlanRid = "/subscriptions/x/resourceGroups/y/providers/Microsoft.Web/serverfarms/plan-prod";

    private static ToolInputValidator NewValidator() => new(
        Options.Create(new AppServicePlansOptions { AllowedResourceIds = { PlanRid } }),
        Options.Create(new AppServiceSitesOptions()),
        Options.Create(new DatabasesOptions
        {
            Allowed =
            {
                new AllowedDatabase { Key = "prod-db", Type = DatabaseType.SqlDatabase, ResourceId = "/subs/x/dbs/y" }
            }
        }),
        Options.Create(new AppInsightsOptions()));

    [Fact]
    public void ValidateChartSeries_PlanSeries_Validates()
    {
        var v = NewValidator();
        var result = v.ValidateChartSeries(new[]
        {
            new ChartSeriesInput("CPU", "AppServicePlanCpu", PlanRid, null, "Average")
        });
        result.Should().HaveCount(1);
        result[0].Metric.Should().Be(ChartMetric.AppServicePlanCpu);
        result[0].Aggregation.Should().Be(MetricAggregation.Average);
        result[0].PlanResourceId.Should().Be(PlanRid);
        result[0].Database.Should().BeNull();
    }

    [Fact]
    public void ValidateChartSeries_DbSeries_Validates()
    {
        var v = NewValidator();
        var result = v.ValidateChartSeries(new[]
        {
            new ChartSeriesInput("DB CPU", "DatabaseCpu", null, "prod-db", "Maximum")
        });
        result[0].Metric.Should().Be(ChartMetric.DatabaseCpu);
        result[0].Aggregation.Should().Be(MetricAggregation.Maximum);
        result[0].Database!.Key.Should().Be("prod-db");
    }

    [Fact]
    public void ValidateChartSeries_MixedSeries_ParsesAll()
    {
        var v = NewValidator();
        var result = v.ValidateChartSeries(new[]
        {
            new ChartSeriesInput("Plan", "AppServicePlanMemory", PlanRid, null, "Average"),
            new ChartSeriesInput("DB",   "DatabaseDtu",          null,    "prod-db", "Average")
        });
        result.Should().HaveCount(2);
        result[0].Metric.Should().Be(ChartMetric.AppServicePlanMemory);
        result[1].Metric.Should().Be(ChartMetric.DatabaseDtu);
    }

    [Fact]
    public void ValidateChartSeries_Empty_Throws()
    {
        NewValidator().Invoking(v => v.ValidateChartSeries(Array.Empty<ChartSeriesInput>()))
            .Should().Throw<ValidationException>();
    }

    [Fact]
    public void ValidateChartSeries_Null_Throws()
    {
        NewValidator().Invoking(v => v.ValidateChartSeries(null))
            .Should().Throw<ValidationException>();
    }

    [Fact]
    public void ValidateChartSeries_TooMany_Throws()
    {
        var v = NewValidator();
        var many = Enumerable.Range(0, 5).Select(_ => new ChartSeriesInput("L", "AppServicePlanCpu", PlanRid, null, "Average")).ToArray();
        v.Invoking(x => x.ValidateChartSeries(many)).Should().Throw<ValidationException>();
    }

    [Fact]
    public void ValidateChartSeries_UnknownMetric_Throws()
    {
        NewValidator().Invoking(v => v.ValidateChartSeries(new[]
        {
            new ChartSeriesInput("L", "BogusMetric", PlanRid, null, "Average")
        })).Should().Throw<ValidationException>();
    }

    [Fact]
    public void ValidateChartSeries_UnknownAggregation_Throws()
    {
        NewValidator().Invoking(v => v.ValidateChartSeries(new[]
        {
            new ChartSeriesInput("L", "AppServicePlanCpu", PlanRid, null, "Bogus")
        })).Should().Throw<ValidationException>();
    }

    [Fact]
    public void ValidateChartSeries_PlanMetricMissingRid_Throws()
    {
        NewValidator().Invoking(v => v.ValidateChartSeries(new[]
        {
            new ChartSeriesInput("L", "AppServicePlanCpu", null, null, "Average")
        })).Should().Throw<ValidationException>();
    }

    [Fact]
    public void ValidateChartSeries_PlanMetricNotAllowlisted_Throws()
    {
        NewValidator().Invoking(v => v.ValidateChartSeries(new[]
        {
            new ChartSeriesInput("L", "AppServicePlanCpu", "/not-allowed", null, "Average")
        })).Should().Throw<ValidationException>();
    }

    [Fact]
    public void ValidateChartSeries_DbMetricMissingKey_Throws()
    {
        NewValidator().Invoking(v => v.ValidateChartSeries(new[]
        {
            new ChartSeriesInput("L", "DatabaseCpu", null, null, "Average")
        })).Should().Throw<ValidationException>();
    }

    [Fact]
    public void ValidateChartSeries_DbMetricUnknownKey_Throws()
    {
        NewValidator().Invoking(v => v.ValidateChartSeries(new[]
        {
            new ChartSeriesInput("L", "DatabaseCpu", null, "unknown-db", "Average")
        })).Should().Throw<ValidationException>();
    }

    [Fact]
    public void ValidateChartSeries_EmptyLabel_Throws()
    {
        NewValidator().Invoking(v => v.ValidateChartSeries(new[]
        {
            new ChartSeriesInput("", "AppServicePlanCpu", PlanRid, null, "Average")
        })).Should().Throw<ValidationException>();
    }

    [Theory]
    [InlineData("RequestsPerMinute")]
    [InlineData("FailedRequestsPerMinute")]
    [InlineData("ExceptionsPerMinute")]
    [InlineData("SnatSuspectedFailuresPerMinute")]
    public void ValidateChartSeries_AppInsightsMetric_RequiresNoTarget(string metric)
    {
        var v = NewValidator();
        var result = v.ValidateChartSeries(new[]
        {
            new ChartSeriesInput("Label", metric, null, null, "Average")
        });
        result.Should().HaveCount(1);
        result[0].PlanResourceId.Should().BeNull();
        result[0].Database.Should().BeNull();
    }

    [Fact]
    public void ValidateChartSeries_MixedPlanAndAppInsights_BothValidate()
    {
        var v = NewValidator();
        var result = v.ValidateChartSeries(new[]
        {
            new ChartSeriesInput("Plan CPU", "AppServicePlanCpu", PlanRid, null, "Average"),
            new ChartSeriesInput("Requests/min", "RequestsPerMinute", null, null, "Average")
        });
        result.Should().HaveCount(2);
        result[0].PlanResourceId.Should().Be(PlanRid);
        result[1].PlanResourceId.Should().BeNull();
        result[1].Database.Should().BeNull();
    }

    [Fact]
    public void ValidateChartSeries_LongLabel_Throws()
    {
        var longLabel = new string('a', 65);
        NewValidator().Invoking(v => v.ValidateChartSeries(new[]
        {
            new ChartSeriesInput(longLabel, "AppServicePlanCpu", PlanRid, null, "Average")
        })).Should().Throw<ValidationException>();
    }
}
