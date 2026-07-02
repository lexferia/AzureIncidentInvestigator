namespace AzureIncidentInvestigator.Application.Reports;

public sealed record Report(string Markdown, DateTimeOffset GeneratedAtUtc, int RedactedItemsCount, string? FileSavedPath);
