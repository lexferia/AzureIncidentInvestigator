using FluentAssertions;
using Xunit;

namespace AzureIncidentInvestigator;

public class KqlTemplateTests
{
    [Fact]
    public void TopExceptions_SubstitutesTopValue()
    {
        var kql = KqlTemplate.TopExceptions(25);
        kql.Should().Contain("top 25");
        kql.Should().NotContain("{TOP}");
    }

    [Theory]
    [InlineData(-5, 1)]
    [InlineData(0, 1)]
    [InlineData(500, 100)]
    [InlineData(50, 50)]
    public void TopExceptions_ClampsValue(int input, int expected)
    {
        var kql = KqlTemplate.TopExceptions(input);
        kql.Should().Contain($"top {expected}");
    }

    [Fact]
    public void AllParameterizedMethods_SubstituteCleanly()
    {
        foreach (var kql in new[]
        {
            KqlTemplate.TopExceptions(10),
            KqlTemplate.FailedRequests(10),
            KqlTemplate.FailedDependencies(10),
            KqlTemplate.TopUserAgents(10, "tostring(client_Browser)"),
            KqlTemplate.TopClientIps(10, "tostring(client_IP)")
        })
        {
            kql.Should().Contain("top 10");
            kql.Should().NotContain("{TOP}");
            kql.Should().NotContain("{USER_AGENT_EXPR}");
            kql.Should().NotContain("{CLIENT_IP_EXPR}");
            kql.Should().NotContainAny("{0}", "{1}");
        }
    }

    [Fact]
    public void StaticTemplates_AreNonEmpty()
    {
        KqlTemplate.StatusCodeBreakdown.Should().NotBeNullOrWhiteSpace();
        KqlTemplate.AppServiceRestarts.Should().NotBeNullOrWhiteSpace();
        KqlTemplate.SnatSuspectFailures.Should().NotBeNullOrWhiteSpace();
    }
}
