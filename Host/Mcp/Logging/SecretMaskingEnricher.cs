using Serilog.Core;
using Serilog.Events;

namespace AzureIncidentInvestigator;

internal sealed class SecretMaskingEnricher : ILogEventEnricher
{
    private static readonly string[] BadSubstrings = { "key", "token", "secret", "password", "authorization" };

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        foreach (var key in logEvent.Properties.Keys.ToArray())
        {
            if (BadSubstrings.Any(b => key.Contains(b, StringComparison.OrdinalIgnoreCase)))
            {
                logEvent.AddOrUpdateProperty(new LogEventProperty(key, new ScalarValue("<masked>")));
            }
        }
    }
}
