namespace AzureIncidentInvestigator.Domain.Crawlers;

public sealed record CrawlerSignal(string Kind, int Weight, string Evidence);
