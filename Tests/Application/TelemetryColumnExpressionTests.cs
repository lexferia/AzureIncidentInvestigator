using FluentAssertions;
using AzureIncidentInvestigator.Application.Queries;
using Xunit;

namespace AzureIncidentInvestigator.Tests.Application;

public class TelemetryColumnExpressionTests
{
    [Fact]
    public void Compile_Null_ReturnsFallback()
    {
        TelemetryColumnExpression.Compile(null).Should().Be("\"\"");
    }

    [Fact]
    public void Compile_Empty_ReturnsFallback()
    {
        TelemetryColumnExpression.Compile(Array.Empty<string>()).Should().Be("\"\"");
    }

    [Fact]
    public void Compile_SingleCustomDimension_ProducesTostringExpression()
    {
        TelemetryColumnExpression.Compile(new[] { "customDimensions:Client IP Address" })
            .Should().Be("tostring(Properties[\"Client IP Address\"])");
    }

    [Fact]
    public void Compile_SingleBuiltIn_ProducesTostringExpression()
    {
        TelemetryColumnExpression.Compile(new[] { "builtIn:ClientIP" })
            .Should().Be("tostring(ClientIP)");
    }

    [Fact]
    public void Compile_MultiSource_ProducesCoalesceChain()
    {
        var result = TelemetryColumnExpression.Compile(new[]
        {
            "customDimensions:Client IP Address",
            "builtIn:ClientIP"
        });
        result.Should().Be("coalesce(tostring(Properties[\"Client IP Address\"]), tostring(ClientIP), \"\")");
    }

    [Fact]
    public void Compile_SourceCaseInsensitive()
    {
        TelemetryColumnExpression.Compile(new[] { "CUSTOMDIMENSIONS:User-Agent" })
            .Should().Be("tostring(Properties[\"User-Agent\"])");
        TelemetryColumnExpression.Compile(new[] { "BUILTIN:ClientIP" })
            .Should().Be("tostring(ClientIP)");
    }

    [Theory]
    [InlineData("missing-colon")]
    [InlineData(":empty-source")]
    [InlineData("customDimensions:")]
    [InlineData("unknownSource:key")]
    [InlineData("")]
    [InlineData("  ")]
    public void Compile_MalformedEntry_Throws(string raw)
    {
        FluentActions.Invoking(() => TelemetryColumnExpression.Compile(new[] { raw }))
            .Should().Throw<InvalidOperationException>();
    }

    [Theory]
    // Quotes/brackets would break the KQL string literal
    [InlineData("customDimensions:bad\"key")]
    [InlineData("customDimensions:bad]key")]
    [InlineData("customDimensions:bad[key")]
    // Semicolons / KQL operators
    [InlineData("customDimensions:bad;key")]
    [InlineData("customDimensions:bad|key")]
    public void Compile_DangerousCustomDimensionKey_Throws(string raw)
    {
        FluentActions.Invoking(() => TelemetryColumnExpression.Compile(new[] { raw }))
            .Should().Throw<InvalidOperationException>();
    }

    [Theory]
    [InlineData("builtIn:1startsWithDigit")]
    [InlineData("builtIn:has-hyphen")]
    [InlineData("builtIn:has.dot")]
    [InlineData("builtIn:has space")]
    [InlineData("builtIn:has\"quote")]
    public void Compile_DangerousBuiltInName_Throws(string raw)
    {
        FluentActions.Invoking(() => TelemetryColumnExpression.Compile(new[] { raw }))
            .Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void Compile_CustomDimensionKey_AllowsCommonChars()
    {
        // Spaces, hyphens, dots, underscores — all common in real workspaces.
        TelemetryColumnExpression.Compile(new[] { "customDimensions:User-Agent" }).Should().NotBeEmpty();
        TelemetryColumnExpression.Compile(new[] { "customDimensions:Client IP Address" }).Should().NotBeEmpty();
        TelemetryColumnExpression.Compile(new[] { "customDimensions:request.id" }).Should().NotBeEmpty();
        TelemetryColumnExpression.Compile(new[] { "customDimensions:CustomKey_2" }).Should().NotBeEmpty();
    }

    [Fact]
    public void Compile_BuiltInColumn_AllowsIdentifierShapes()
    {
        TelemetryColumnExpression.Compile(new[] { "builtIn:client_IP" }).Should().NotBeEmpty();
        TelemetryColumnExpression.Compile(new[] { "builtIn:client_CountryOrRegion" }).Should().NotBeEmpty();
        TelemetryColumnExpression.Compile(new[] { "builtIn:_underscore_first" }).Should().NotBeEmpty();
    }
}
