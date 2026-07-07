using System.Text.RegularExpressions;

namespace AzureIncidentInvestigator;

/// <summary>
/// Compiles operator-configured telemetry column sources into safe KQL fragments.
///
/// Each entry is a string of the form "&lt;source&gt;:&lt;key&gt;" where source is
/// either "customDimensions" or "builtIn". Multiple entries form a coalesce
/// chain. Keys are regex-validated so the generated KQL is well-formed and
/// cannot break out of the string literal context inside the template.
///
/// The "customDimensions" source maps to the workspace-based Application Insights
/// dynamic column "Properties" (classic AI called this bag "customDimensions"); the
/// keyword is kept for familiarity. "builtIn" keys must be workspace column names
/// (e.g. ClientIP, ClientCountryOrRegion), not the classic client_IP names.
///
/// Examples (valid):
///   "customDimensions:Client IP Address"         -> tostring(Properties["Client IP Address"])
///   "builtIn:ClientIP"                           -> tostring(ClientIP)
///   ["customDimensions:User-Agent","builtIn:ClientBrowser"]
///        -> coalesce(tostring(Properties["User-Agent"]), tostring(ClientBrowser), "")
/// </summary>
internal static partial class TelemetryColumnExpression
{
    // customDimensions keys: letters, digits, space, underscore, hyphen, dot.
    // Excludes brackets, quotes, semicolons — anything that could break out of the literal.
    [GeneratedRegex(@"^[A-Za-z0-9 _\-\.]{1,128}$", RegexOptions.Compiled)]
    private static partial Regex CustomDimensionKeyRegex();

    // Built-in column names: standard identifier shape.
    [GeneratedRegex(@"^[A-Za-z_][A-Za-z0-9_]{0,63}$", RegexOptions.Compiled)]
    private static partial Regex BuiltInColumnRegex();

    /// <summary>
    /// Compile a list of "source:key" entries into a single coalesce(tostring(...)) expression.
    /// Throws <see cref="InvalidOperationException"/> if any entry is malformed or unsafe.
    /// </summary>
    public static string Compile(IReadOnlyList<string>? sources, string fallback = "\"\"")
    {
        if (sources is null || sources.Count == 0)
        {
            return fallback;
        }

        var parts = new List<string>(sources.Count);
        foreach (var raw in sources)
        {
            if (string.IsNullOrWhiteSpace(raw))
            {
                throw new InvalidOperationException("Telemetry column source must not be empty.");
            }

            var colon = raw.IndexOf(':');
            if (colon <= 0 || colon == raw.Length - 1)
            {
                throw new InvalidOperationException(
                    $"Invalid telemetry column source '{raw}'. Expected '<source>:<key>'.");
            }

            var source = raw[..colon].Trim();
            var key = raw[(colon + 1)..].Trim();

            if (string.Equals(source, "customDimensions", StringComparison.OrdinalIgnoreCase))
            {
                if (!CustomDimensionKeyRegex().IsMatch(key))
                {
                    throw new InvalidOperationException(
                        $"Invalid customDimensions key '{key}'. Allowed: A-Z, a-z, 0-9, space, '_', '-', '.', 1-128 chars.");
                }
                parts.Add($"tostring(Properties[\"{key}\"])");
            }
            else if (string.Equals(source, "builtIn", StringComparison.OrdinalIgnoreCase))
            {
                if (!BuiltInColumnRegex().IsMatch(key))
                {
                    throw new InvalidOperationException(
                        $"Invalid built-in column '{key}'. Allowed: identifier shape, 1-64 chars.");
                }
                parts.Add($"tostring({key})");
            }
            else
            {
                throw new InvalidOperationException(
                    $"Unknown telemetry column source '{source}'. Expected 'customDimensions' or 'builtIn'.");
            }
        }

        return parts.Count == 1 ? parts[0] : $"coalesce({string.Join(", ", parts)}, {fallback})";
    }
}
