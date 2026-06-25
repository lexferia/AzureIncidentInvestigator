namespace AzureIncidentInvestigator.Domain.Crawlers;

public enum UserAgentClass
{
    Unknown = 0,
    Browser = 1,
    KnownBot = 2,
    AICrawler = 3,
    Headless = 4,
    Malformed = 5
}
