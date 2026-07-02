namespace AzureIncidentInvestigator;

public sealed record Report(string Markdown, DateTimeOffset GeneratedAtUtc, int RedactedItemsCount, string? FileSavedPath);
