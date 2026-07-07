using System.Net.Http.Headers;
using Azure.Core;

namespace AzureIncidentInvestigator;

internal sealed class AzureManagementAuthHandler : DelegatingHandler
{
    private static readonly string[] Scopes = { "https://management.azure.com/.default" };
    private readonly TokenCredential _credential;

    public AzureManagementAuthHandler(TokenCredential credential) => _credential = credential;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var token = await _credential.GetTokenAsync(new TokenRequestContext(Scopes), cancellationToken);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
        return await base.SendAsync(request, cancellationToken);
    }
}
