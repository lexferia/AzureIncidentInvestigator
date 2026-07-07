// =============================================================================
// The MCP tools (one class per feature under Features/*/) are the public attack
// surface of this server.
//
// EVERY tool is a SAFE, CONSTRAINED operation. The following capabilities are
// INTENTIONALLY ABSENT and must NEVER be added without a security review:
//
//   * run_kql / query_logs   — would defeat the parameterized-template guarantee
//   * fetch_url / http_get    — SSRF risk via a generic HTTP client
//   * execute_command         — game over for process confinement
//   * read_file / list_dir    — exfil channel
//   * get_config / get_env    — secret exposure
//   * any Azure ARM mutation  — this server is strictly read-only
//
// See docs/superpowers/specs/2026-05-26-azure-incident-investigator-design.md section 5.2
// =============================================================================

using System.Text.Json;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Protocol;

namespace AzureIncidentInvestigator;

/// <summary>Logger category marker for tool invocations.</summary>
public sealed class ToolMarker;

/// <summary>
/// Shared invocation wrapper for every MCP tool: rate-limiting, structured logging,
/// and translation of validation/configuration/authentication/upstream failures into
/// stable JSON error payloads. Feature tool classes call these instead of duplicating
/// the try/catch envelope.
/// </summary>
internal static class ToolExecution
{
    public static async Task<object> RunAsync(
        string toolName,
        ToolRateLimiter limiter,
        ILogger log,
        CancellationToken ct,
        Func<Task<object>> body)
    {
        var correlationId = Guid.NewGuid().ToString("N");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            if (!await limiter.TryAcquireAsync(toolName, ct))
            {
                log.LogWarning("Rate limited {Tool} {CorrelationId}", toolName, correlationId);
                return new { error = "rate_limited", tool = toolName };
            }

            var result = await body();
            log.LogInformation("tool.invoked {Tool} {CorrelationId} duration={Duration}ms outcome=ok",
                toolName, correlationId, sw.ElapsedMilliseconds);
            return result;
        }
        catch (ValidationException vex)
        {
            log.LogWarning("tool.invoked {Tool} {CorrelationId} duration={Duration}ms outcome=validation param={Param}",
                toolName, correlationId, sw.ElapsedMilliseconds, vex.ParameterName);
            return new { error = "validation", parameter = vex.ParameterName, message = vex.Message };
        }
        catch (ConfigurationException cex)
        {
            log.LogWarning("tool.invoked {Tool} {CorrelationId} duration={Duration}ms outcome=configuration setting={Setting}",
                toolName, correlationId, sw.ElapsedMilliseconds, cex.Setting);
            return new { error = "configuration", setting = cex.Setting, message = cex.Message, retryable = false };
        }
        catch (AuthenticationException aex)
        {
            log.LogWarning(aex, "tool.invoked {Tool} {CorrelationId} duration={Duration}ms outcome=authentication",
                toolName, correlationId, sw.ElapsedMilliseconds);
            return new { error = "authentication", message = aex.Message, retryable = false };
        }
        catch (OperationCanceledException)
        {
            log.LogInformation("tool.invoked {Tool} {CorrelationId} duration={Duration}ms outcome=cancelled",
                toolName, correlationId, sw.ElapsedMilliseconds);
            return new { error = "cancelled" };
        }
        catch (Exception ex)
        {
            log.LogError(ex, "tool.invoked {Tool} {CorrelationId} duration={Duration}ms outcome=upstream",
                toolName, correlationId, sw.ElapsedMilliseconds);
            return new { error = "upstream", message = "An upstream error occurred. See server logs." };
        }
    }

    public static async Task<CallToolResult> RunCallToolAsync(
        string toolName,
        ToolRateLimiter limiter,
        ILogger log,
        CancellationToken ct,
        Func<Task<CallToolResult>> body)
    {
        var correlationId = Guid.NewGuid().ToString("N");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            if (!await limiter.TryAcquireAsync(toolName, ct))
            {
                log.LogWarning("Rate limited {Tool} {CorrelationId}", toolName, correlationId);
                return ErrorResult($"{{\"error\":\"rate_limited\",\"tool\":\"{toolName}\"}}");
            }

            var result = await body();
            log.LogInformation("tool.invoked {Tool} {CorrelationId} duration={Duration}ms outcome=ok",
                toolName, correlationId, sw.ElapsedMilliseconds);
            return result;
        }
        catch (ValidationException vex)
        {
            log.LogWarning("tool.invoked {Tool} {CorrelationId} duration={Duration}ms outcome=validation param={Param}",
                toolName, correlationId, sw.ElapsedMilliseconds, vex.ParameterName);
            var payload = JsonSerializer.Serialize(new { error = "validation", parameter = vex.ParameterName, message = vex.Message });
            return ErrorResult(payload);
        }
        catch (ConfigurationException cex)
        {
            log.LogWarning("tool.invoked {Tool} {CorrelationId} duration={Duration}ms outcome=configuration setting={Setting}",
                toolName, correlationId, sw.ElapsedMilliseconds, cex.Setting);
            var payload = JsonSerializer.Serialize(new { error = "configuration", setting = cex.Setting, message = cex.Message, retryable = false });
            return ErrorResult(payload);
        }
        catch (AuthenticationException aex)
        {
            log.LogWarning(aex, "tool.invoked {Tool} {CorrelationId} duration={Duration}ms outcome=authentication",
                toolName, correlationId, sw.ElapsedMilliseconds);
            var payload = JsonSerializer.Serialize(new { error = "authentication", message = aex.Message, retryable = false });
            return ErrorResult(payload);
        }
        catch (OperationCanceledException)
        {
            log.LogInformation("tool.invoked {Tool} {CorrelationId} duration={Duration}ms outcome=cancelled",
                toolName, correlationId, sw.ElapsedMilliseconds);
            return ErrorResult("{\"error\":\"cancelled\"}");
        }
        catch (Exception ex)
        {
            log.LogError(ex, "tool.invoked {Tool} {CorrelationId} duration={Duration}ms outcome=upstream",
                toolName, correlationId, sw.ElapsedMilliseconds);
            return ErrorResult("{\"error\":\"upstream\",\"message\":\"An upstream error occurred. See server logs.\"}");
        }
    }

    private static CallToolResult ErrorResult(string jsonPayload) => new()
    {
        IsError = true,
        Content = { new TextContentBlock { Text = jsonPayload } }
    };
}
