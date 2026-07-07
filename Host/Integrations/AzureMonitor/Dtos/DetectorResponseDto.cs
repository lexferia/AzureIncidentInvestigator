using System.Text.Json.Serialization;

namespace AzureIncidentInvestigator;

internal sealed class DetectorResponseDto
{
    [JsonPropertyName("properties")] public DetectorPropertiesDto? Properties { get; set; }
}

internal sealed class DetectorPropertiesDto
{
    [JsonPropertyName("status")] public DetectorStatusDto? Status { get; set; }
    [JsonPropertyName("dataset")] public List<DetectorDatasetDto>? Dataset { get; set; }
}

internal sealed class DetectorStatusDto
{
    [JsonPropertyName("message")] public string? Message { get; set; }
    [JsonPropertyName("statusId")] public int? StatusId { get; set; }
}

internal sealed class DetectorDatasetDto
{
    [JsonPropertyName("table")] public DetectorTableDto? Table { get; set; }
    [JsonPropertyName("renderingProperties")] public DetectorRenderingDto? RenderingProperties { get; set; }
}

internal sealed class DetectorTableDto
{
    [JsonPropertyName("columns")] public List<DetectorColumnDto>? Columns { get; set; }
    [JsonPropertyName("rows")] public List<List<object?>>? Rows { get; set; }
}

internal sealed class DetectorColumnDto
{
    [JsonPropertyName("columnName")] public string? ColumnName { get; set; }
}

internal sealed class DetectorRenderingDto
{
    [JsonPropertyName("title")] public string? Title { get; set; }
    [JsonPropertyName("description")] public string? Description { get; set; }
}
