namespace AzureIncidentInvestigator;

public sealed record CrawlerSignal(string Kind, int Weight, string Evidence);
