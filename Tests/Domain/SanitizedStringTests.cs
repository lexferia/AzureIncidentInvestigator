using FluentAssertions;
using AzureIncidentInvestigator.Domain.Shared;
using Xunit;

namespace AzureIncidentInvestigator.Tests.Domain;

public class SanitizedStringTests
{
    [Fact]
    public void Value_ReturnsValue()
    {
        var s = new SanitizedString("hello");
        string actual = s.Value;
        actual.Should().Be("hello");
    }

    [Fact]
    public void Empty_HasEmptyValue()
    {
        SanitizedString.Empty.Value.Should().BeEmpty();
    }
}
