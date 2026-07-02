using System.Text.Json.Serialization;

namespace AzureIncidentInvestigator;

internal sealed class GetMonitorsResponse
{
    [JsonPropertyName("stat")] public string? Stat { get; set; }
    [JsonPropertyName("monitors")] public List<MonitorDto>? Monitors { get; set; }
    [JsonPropertyName("error")] public ErrorDto? Error { get; set; }
}

internal sealed class MonitorDto
{
    [JsonPropertyName("id")] public long Id { get; set; }
    [JsonPropertyName("friendly_name")] public string? FriendlyName { get; set; }
    [JsonPropertyName("url")] public string? Url { get; set; }
    [JsonPropertyName("status")] public int Status { get; set; }
    [JsonPropertyName("interval")] public int Interval { get; set; }
    [JsonPropertyName("logs")] public List<LogDto>? Logs { get; set; }
}

internal sealed class LogDto
{
    [JsonPropertyName("id")] public long Id { get; set; }
    [JsonPropertyName("type")] public int Type { get; set; }
    [JsonPropertyName("datetime")] public long Datetime { get; set; }
    [JsonPropertyName("reason")] public ReasonDto? Reason { get; set; }
    [JsonPropertyName("duration")] public int? Duration { get; set; }
}

internal sealed class ReasonDto
{
    [JsonPropertyName("code")] public string? Code { get; set; }
    [JsonPropertyName("detail")] public string? Detail { get; set; }
}

internal sealed class ErrorDto
{
    [JsonPropertyName("type")] public string? Type { get; set; }
    [JsonPropertyName("message")] public string? Message { get; set; }
}
