using System.Text;
using Microsoft.Extensions.Options;

namespace AzureIncidentInvestigator;

internal sealed class UptimeRobotAuthHandler : DelegatingHandler
{
    private readonly IOptionsMonitor<UptimeRobotOptions> _options;

    public UptimeRobotAuthHandler(IOptionsMonitor<UptimeRobotOptions> options) => _options = options;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var apiKey = _options.CurrentValue.ApiKey;
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            throw new ConfigurationException(
                "UptimeRobot:ApiKey",
                "UptimeRobot:ApiKey is not configured. Run: dotnet user-secrets set \"UptimeRobot:ApiKey\" \"...\" --project Host");
        }

        if (request.Content is not null)
        {
            var existingBody = await request.Content.ReadAsStringAsync(cancellationToken);
            var newBody = string.IsNullOrEmpty(existingBody)
                ? $"api_key={apiKey}&format=json"
                : $"api_key={apiKey}&format=json&{existingBody}";
            request.Content = new StringContent(newBody, Encoding.UTF8, "application/x-www-form-urlencoded");
        }
        else
        {
            request.Content = new StringContent($"api_key={apiKey}&format=json", Encoding.UTF8, "application/x-www-form-urlencoded");
        }

        return await base.SendAsync(request, cancellationToken);
    }
}
