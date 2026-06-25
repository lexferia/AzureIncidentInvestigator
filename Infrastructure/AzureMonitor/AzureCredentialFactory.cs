using Azure.Core;
using Azure.Identity;

namespace AzureIncidentInvestigator.Infrastructure.AzureMonitor;

internal static class AzureCredentialFactory
{
    public static TokenCredential Create()
    {
        // Excludes interactive and environment flows. Locally, the Azure CLI cached token wins.
        return new DefaultAzureCredential(new DefaultAzureCredentialOptions
        {
            ExcludeInteractiveBrowserCredential = true,
            ExcludeEnvironmentCredential = true
        });
    }
}
