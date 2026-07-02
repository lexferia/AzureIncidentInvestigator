namespace AzureIncidentInvestigator;

/// <summary>
/// Azure authentication failed: no usable credential was found on the server host, or
/// token acquisition failed. This is an environment/setup problem, not a transient fault —
/// retrying the same call will not help until credentials are fixed (e.g. `az login`).
/// </summary>
public sealed class AuthenticationException : Exception
{
    public AuthenticationException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}
