using Azure.Core;
using Azure.Identity;

namespace AzureIncidentInvestigator;

internal static class AzureCredentialFactory
{
    public static TokenCredential Create()
    {
        // Keep only the two credentials this server actually uses:
        //   - Azure CLI (local dev: `az login`)
        //   - Managed Identity (production on Azure)
        // The excluded dev credentials (Visual Studio / VS Code / Azure PowerShell /
        // azd) launch external processes to fetch tokens; on this box they time out and,
        // because the first token fetch runs inside the per-query timeout budget, that
        // cancellation surfaced intermittently as "DefaultAzureCredential authentication
        // failed". Dropping them makes the first query reliable instead of flaky.
        return new DefaultAzureCredential(new DefaultAzureCredentialOptions
        {
            ExcludeInteractiveBrowserCredential = true,
            ExcludeEnvironmentCredential = true,
            ExcludeVisualStudioCredential = true,
            ExcludeVisualStudioCodeCredential = true,
            ExcludeAzurePowerShellCredential = true,
            ExcludeAzureDeveloperCliCredential = true
        });
    }
}
