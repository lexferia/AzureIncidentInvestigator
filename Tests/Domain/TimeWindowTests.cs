using FluentAssertions;
using Xunit;

namespace AzureIncidentInvestigator;

public class TimeWindowTests
{
    [Fact]
    public void Construct_WhenEndBeforeStart_Throws()
    {
        var start = DateTimeOffset.UtcNow;
        var end = start.AddMinutes(-1);
        var act = () => new TimeWindow(start, end);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Construct_WhenWindowValid_ReturnsInstance()
    {
        var start = DateTimeOffset.UtcNow.AddHours(-1);
        var end = DateTimeOffset.UtcNow;
        var w = new TimeWindow(start, end);
        w.StartUtc.Should().Be(start);
        w.EndUtc.Should().Be(end);
        w.Duration.Should().BeCloseTo(TimeSpan.FromHours(1), TimeSpan.FromSeconds(1));
    }
}
