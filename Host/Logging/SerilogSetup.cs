using Microsoft.Extensions.Configuration;
using Serilog;
using Serilog.Events;

namespace AzureIncidentInvestigator.Host.Logging;

internal static class SerilogSetup
{
    public static LoggerConfiguration Configure(LoggerConfiguration config, IConfiguration configuration)
    {
        var logRoot = Environment.ExpandEnvironmentVariables(@"%LOCALAPPDATA%\AzureIncidentInvestigator\logs");
        Directory.CreateDirectory(logRoot);

        return config
            .ReadFrom.Configuration(configuration)
            .Enrich.FromLogContext()
            .Enrich.With(new SecretMaskingEnricher())
            .Destructure.ByTransforming<HttpRequestMessage>(_ => "<HttpRequestMessage suppressed>")
            .Destructure.ByTransforming<HttpResponseMessage>(_ => "<HttpResponseMessage suppressed>")
            .Destructure.ByTransforming<Azure.Core.TokenCredential>(_ => "<TokenCredential suppressed>")
            .WriteTo.Console(
                standardErrorFromLevel: LogEventLevel.Verbose,
                outputTemplate: "{Timestamp:HH:mm:ss.fff} [{Level:u3}] {Message:lj} {Properties:j}{NewLine}{Exception}")
            .WriteTo.File(
                path: Path.Combine(logRoot, "mcp-.log"),
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 14,
                outputTemplate: "{Timestamp:o} [{Level:u3}] {Message:lj} {Properties:j}{NewLine}{Exception}");
    }
}
