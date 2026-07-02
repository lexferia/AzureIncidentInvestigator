using Azure.Identity;

namespace AzureIncidentInvestigator;

/// <summary>
/// Wraps Azure SDK calls so that credential/token failures surface as a domain
/// <see cref="AuthenticationException"/> with actionable guidance, instead of leaking a
/// raw Azure.Identity exception (which the tool layer would otherwise report as a generic
/// "upstream" error and the model would pointlessly retry).
/// </summary>
internal static class AzureAuthGuard
{
    public const string Guidance =
        "Azure authentication failed: no usable Azure credential was found on the server host. " +
        "Ensure `az login` has been run on that machine (or a managed identity is configured), then retry. " +
        "This is a setup issue — retrying without fixing credentials will not help.";

    /// <summary>
    /// Runs <paramref name="call"/>, translating Azure.Identity credential failures into
    /// <see cref="AuthenticationException"/>. <see cref="CredentialUnavailableException"/>
    /// derives from <see cref="AuthenticationFailedException"/>, so both are covered.
    /// </summary>
    public static async Task<T> GuardAsync<T>(Func<Task<T>> call)
    {
        try
        {
            return await call();
        }
        catch (AuthenticationFailedException ex)
        {
            throw new AuthenticationException(Guidance, ex);
        }
    }
}
