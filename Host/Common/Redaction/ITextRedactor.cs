
namespace AzureIncidentInvestigator;

public interface ITextRedactor
{
    string Redact(string input);
    SanitizedString Wrap(string input);
    int LastRedactionCount { get; }
    void ResetCount();
}
