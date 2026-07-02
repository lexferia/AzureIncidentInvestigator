using FluentAssertions;
using Xunit;

namespace AzureIncidentInvestigator;

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
