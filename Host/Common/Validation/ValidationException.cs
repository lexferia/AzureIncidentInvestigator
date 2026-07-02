namespace AzureIncidentInvestigator;

public sealed class ValidationException : Exception
{
    public string ParameterName { get; }

    public ValidationException(string parameterName, string message)
        : base(message)
    {
        ParameterName = parameterName;
    }
}
