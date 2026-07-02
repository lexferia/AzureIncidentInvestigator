using FluentAssertions;
using Xunit;

namespace AzureIncidentInvestigator;

public class CrawlerClassifierTests
{
    private static readonly CrawlerClassifier Classifier = new();

    [Fact]
    public void Classify_GoogleBot_IsKnownBot()
    {
        var result = Classifier.Classify(new CrawlerCandidate(
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "203.0.113.0/24", 100, 5, 100));
        result.Classification.Should().Be(UserAgentClass.KnownBot);
    }

    [Fact]
    public void Classify_GptBot_IsAICrawler()
    {
        var result = Classifier.Classify(new CrawlerCandidate(
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.0; +https://openai.com/gptbot",
            "203.0.113.0/24", 50, 0, 50));
        result.Classification.Should().Be(UserAgentClass.AICrawler);
    }

    [Fact]
    public void Classify_HeadlessChrome_IsHeadless()
    {
        var result = Classifier.Classify(new CrawlerCandidate(
            "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/120.0.0.0",
            "203.0.113.0/24", 200, 50, 200));
        result.Classification.Should().Be(UserAgentClass.Headless);
        result.Signals.Should().Contain(s => s.Kind == "headless");
    }

    [Fact]
    public void Classify_EmptyUA_IsMalformedWithHighWeight()
    {
        var result = Classifier.Classify(new CrawlerCandidate(
            "", "203.0.113.0/24", 100, 10, 100));
        result.Classification.Should().Be(UserAgentClass.Malformed);
        result.Signals.Sum(s => s.Weight).Should().BeGreaterThanOrEqualTo(30);
    }

    [Fact]
    public void Classify_HighRequestRate_AddsWeight()
    {
        var result = Classifier.Classify(new CrawlerCandidate(
            "MyCustomBot/1.0", "203.0.113.0/24", 5000, 100, 5000));
        result.Signals.Should().Contain(s => s.Kind == "high-rate");
        result.Risk.Value.Should().BeGreaterThanOrEqualTo(20);
    }

    [Fact]
    public void Classify_High404Ratio_AddsWeight()
    {
        var result = Classifier.Classify(new CrawlerCandidate(
            "scraper/1.0", "203.0.113.0/24", 100, 80, 100));
        result.Signals.Should().Contain(s => s.Kind == "high-404-ratio");
    }

    [Fact]
    public void Classify_NormalBrowser_BenignBucket()
    {
        var result = Classifier.Classify(new CrawlerCandidate(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "203.0.113.0/24", 30, 1, 30));
        result.Risk.Bucket.Should().Be(RiskBucket.Benign);
    }

    [Fact]
    public void Classify_MultipleSignals_HitsSuspicious()
    {
        var result = Classifier.Classify(new CrawlerCandidate(
            "", "203.0.113.0/24", 10000, 8000, 10000));
        result.Risk.Bucket.Should().Be(RiskBucket.Suspicious);
    }
}
