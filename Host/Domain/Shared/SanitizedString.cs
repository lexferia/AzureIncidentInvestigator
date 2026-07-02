namespace AzureIncidentInvestigator.Domain.Shared;

/// <summary>Wraps text that originated from an untrusted external source (telemetry, UA, URL).</summary>
public readonly record struct SanitizedString(string Value)
{
    public static SanitizedString Empty { get; } = new(string.Empty);
    public override string ToString() => Value;
}
