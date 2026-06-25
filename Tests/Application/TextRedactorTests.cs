using FluentAssertions;
using AzureIncidentInvestigator.Application.Redaction;
using Xunit;

namespace AzureIncidentInvestigator.Tests.Application;

public class TextRedactorTests
{
    [Fact]
    public void Redact_Email_IsMasked()
    {
        var r = new TextRedactor();
        r.Redact("contact me at jane.doe@example.com please").Should().Contain("<email>");
    }

    [Fact]
    public void Redact_Jwt_IsMasked()
    {
        var r = new TextRedactor();
        var jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        r.Redact($"Token: {jwt}").Should().Contain("<jwt>").And.NotContain(jwt);
    }

    [Fact]
    public void Redact_Bearer_IsMasked()
    {
        var r = new TextRedactor();
        r.Redact("Authorization: Bearer abc123def456ghi789").Should().Contain("Bearer <token>");
    }

    [Fact]
    public void Redact_IPv4_LastOctetMasked()
    {
        var r = new TextRedactor();
        r.Redact("from 203.0.113.45 today").Should().Contain("203.0.113.x").And.NotContain("113.45");
    }

    [Fact]
    public void Redact_ConnectionString_AccountKey_Masked()
    {
        var r = new TextRedactor();
        r.Redact("AccountKey=Zm9vYmFyYmF6OTk5OTk5OTk=").Should().Contain("AccountKey=<redacted>");
    }

    [Fact]
    public void Redact_UrlQueryToken_Masked()
    {
        var r = new TextRedactor();
        r.Redact("https://site/api?token=abc123secret&id=42").Should().Contain("token=<redacted>");
    }

    [Fact]
    public void Wrap_StripsControlChars()
    {
        var r = new TextRedactor();
        r.Wrap("helloworld").Value.Should().Be("helloworld");
    }

    [Fact]
    public void Wrap_TruncatesToCap()
    {
        var r = new TextRedactor();
        // Space-separated so no 32+ char run triggers secret redaction; exercises truncation only.
        var s = string.Join(' ', Enumerable.Repeat("word", 1000));
        r.Wrap(s).Value.Length.Should().Be(2048);
    }

    [Fact]
    public void LastRedactionCount_TracksHits()
    {
        var r = new TextRedactor();
        r.Redact("a@b.com and c@d.com from 1.2.3.4");
        r.LastRedactionCount.Should().BeGreaterThanOrEqualTo(3);
    }
}
