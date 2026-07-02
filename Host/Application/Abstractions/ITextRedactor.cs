using AzureIncidentInvestigator.Domain.Shared;

namespace AzureIncidentInvestigator.Application.Abstractions;

public interface ITextRedactor
{
    string Redact(string input);
    SanitizedString Wrap(string input);
    int LastRedactionCount { get; }
    void ResetCount();
}
