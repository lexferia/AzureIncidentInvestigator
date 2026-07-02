namespace AzureIncidentInvestigator.Application.Errors;

/// <summary>
/// A required configuration value or secret is missing — e.g. the UptimeRobot API key
/// (a user-secret) is unset, or AppInsights:WorkspaceId is not configured.
/// This is a setup problem, not a transient fault: retrying the same call will not help
/// until an operator fixes the configuration.
/// </summary>
public sealed class ConfigurationException : Exception
{
    /// <summary>The configuration key or secret that is missing (e.g. "UptimeRobot:ApiKey").</summary>
    public string Setting { get; }

    public ConfigurationException(string setting, string message) : base(message)
    {
        Setting = setting;
    }
}
