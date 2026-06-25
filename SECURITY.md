# Security Model

This document describes the security boundaries, threat model, and defensive posture of `AzureIncidentInvestigator`. It is intended for engineers reviewing or extending the server, and for security reviewers gating production use.

## 1. Threat model (one paragraph)

The MCP server runs as a child process of Claude Desktop or Claude Code. **Claude is treated as an untrusted client**: every tool parameter is bounded and validated. Azure and UptimeRobot responses are treated as **untrusted output**: telemetry strings (user-agents, request URLs, exception messages, log text) may contain prompt-injection payloads, so they are length-capped, control-char-stripped, and redacted (emails, JWTs, partial IPs, secret patterns) before being returned to Claude. No tool accepts free-form KQL, shell, or URLs. The host process has no filesystem write access except a single configurable `Reports:OutputDirectory` (canonicalized + jailed). The server holds **read-only** Azure permissions and a **read-only** UptimeRobot key.

## 2. Authentication boundary

```
Claude  →  MCP stdio  →  Host  →  Application  →  Infrastructure  →  Azure / UptimeRobot
   ▲                                                                        ▲
   │  no credentials cross this line                                        │  credentials resolved here, locally
```

- **Azure:** `DefaultAzureCredential` only. Locally, the Azure CLI cached token wins. Interactive-browser and environment-variable credentials are explicitly excluded (see `AzureCredentialFactory`).
- **UptimeRobot:** API key loaded from .NET User Secrets. Injected via a `DelegatingHandler` (`UptimeRobotAuthHandler`) inside the typed `HttpClient`. Never logged, never returned by any tool.
- No credential type is exposed to MCP tools. Tool methods receive only fully-built service interfaces from DI — they cannot see, derive, or print credentials.

## 3. Input validation

Centralized in `Application/Validation/ToolInputValidator.cs`. Every tool runs validation **before** any I/O.

| Parameter | Rule |
|---|---|
| `days` | Clamp `[1, 30]` |
| `top` | Clamp `[1, 100]` |
| `startTimeUtc / endTimeUtc` | `end > start`; `end ≤ now + 1min`; window ≤ `AppInsights:MaxQueryWindowDays` (default 7) |
| `incidentId` | Regex `^\d{1,20}:\d{1,20}$` |
| `appServicePlanResourceId` | Exact match against `AppServicePlans:AllowedResourceIds` |
| `appServiceSiteResourceId` | Exact match against `AppServiceSites:AllowedResourceIds` |
| `databaseKey` | Exact match against `Databases:Allowed[].Key` |
| Any string | Length ≤ 256, no control chars (`ValidateString`) |

A `ValidationException` becomes a structured MCP error result (`{ "error": "validation", ... }`). There is no "best-effort" mode.

## 4. Output sanitization

Every external string passes through `ITextRedactor.Wrap()` before returning to Claude:

1. Strip control chars (`\x00-\x08`, `\x0B-\x0C`, `\x0E-\x1F`, `\x7F`)
2. Email → `<email>`
3. JWT-shaped strings → `<jwt>`
4. `Bearer <token>` → `Bearer <token>`
5. `AccountKey=` / `Password=` / `SharedAccessKey=` / `SharedAccessSignature=` / `ApiKey=` → `<key>=<redacted>`
6. URL query-string values for `key|token|password|secret|sig|signature|code` → `<redacted>`
7. IPv4 last octet masked (`203.0.113.45` → `203.0.113.x`)
8. 32+ char hex / base64 runs → `<secret>`
9. Length cap 2,048 chars per string

Each `analyze_incident` / `generate_incident_report` result returns a `redactedItemsCount`.

## 5. Prompt-injection defense

- Telemetry strings are wrapped in the `SanitizedString` value type.
- Markdown reports surround untrusted text with `«untrusted» ... «/untrusted»` markers, documented here and in the README.
- **No code path interprets telemetry as instruction.** Tool routing is compile-time attribute-driven (`[McpServerTool]`); there is no late-bound dispatch on telemetry content.
- The redactor is the primary defense; the markers are a UX cue for the human reader.

## 6. Logging policy

- Serilog writes to **stderr** only (stdout is the MCP JSON-RPC wire — polluting it breaks the protocol).
- File sink: `%LOCALAPPDATA%\AzureIncidentInvestigator\logs\mcp-YYYYMMDD.log` (rolling daily, 14-day retention).
- Per tool call: one structured event `tool.invoked { Tool, CorrelationId, Duration, outcome }` where outcome ∈ `ok | validation | cancelled | upstream`.
- `SecretMaskingEnricher` masks any property whose key contains `key`, `token`, `secret`, `password`, or `authorization` → `<masked>`.
- Destructuring of `HttpRequestMessage`, `HttpResponseMessage`, and `TokenCredential` is suppressed.

## 7. Filesystem isolation

- Exactly one writable directory: `Reports:OutputDirectory` (default `%LOCALAPPDATA%\AzureIncidentInvestigator\reports\`).
- On save: the path is canonicalized with `Path.GetFullPath` and prefix-checked against the configured root (defends against `../` traversal). Filenames are server-generated — Claude cannot influence them.
- No tool reads a file from disk and returns its contents.

## 8. Rate limiting

`System.Threading.RateLimiting` token bucket, default 30 calls/min per tool (`RateLimits:PerToolPerMinute`). Exhaustion returns `{ "error": "rate_limited", "tool": "..." }`. Prevents accidental Azure-side throttling during agentic loops.

## 9. Resiliency

- `AddStandardResilienceHandler` (Polly v8) on the UptimeRobot `HttpClient` — retries, timeout, circuit breaker.
- Azure Monitor SDK has built-in retries; the App Insights query path adds a per-query timeout (`AppInsights:QueryTimeoutSeconds`).
- `CancellationToken` from the MCP host is forwarded to every async call.
- A top-level `try/catch` in `InvestigationTools.RunAsync` translates all exceptions into structured MCP error results — exceptions never escape to the JSON-RPC wire (which would kill the server).

## 10. Azure RBAC (least privilege)

| Role | Scope | Why |
|---|---|---|
| Log Analytics Reader | Workspace | All KQL queries |
| Application Insights Reader | App Insights resource | Legacy clients |
| Monitoring Reader | Each allowlisted App Service Plan | Plan metrics |
| Monitoring Reader | Each allowlisted App Service Site | Site metrics (if added later) |
| Monitoring Reader | Each allowlisted Database resource | DB metrics |

**No Contributor, no Owner, no write capability anywhere.**

## 11. Hard refusals (deliberately absent)

These tools are not implemented — by design, not by oversight:

| Refused tool | Why |
|---|---|
| `run_kql` / `query_logs` | Defeats the parameterized-template guarantee |
| `fetch_url` / `http_get` | Generic HTTP client → SSRF risk |
| `execute_command` / `run_powershell` | Process confinement break |
| `read_file` / `list_directory` | Exfiltration channel |
| `get_config` / `get_env` | Secret exposure |
| Any Azure ARM mutation method | Server is strictly read-only |

A comment block at the top of `Host/Tools/InvestigationTools.cs` mirrors this list with rationale. Adding anything from it requires a security review and an update to this document.

## 12. Extension safety checklist

When adding a new tool, the engineer **must**:

1. Use bounded primitive parameters — no `string` that flows directly into a query.
2. Add validation to `ToolInputValidator`.
3. If the tool accepts a resource identifier, add an allowlist in config and a validator check.
4. Wrap any returned external string in `ITextRedactor.Wrap()`.
5. Use the `InvestigationTools.RunAsync` wrapper for logging, rate-limiting, and error translation.
6. Add unit tests for the validator and any pure logic.
7. Update README and SECURITY.md.

## 13. Out-of-scope considerations

- **Network egress:** the host has unrestricted egress; pinning outbound to `*.uptimerobot.com`, `*.loganalytics.io`, `*.monitor.azure.com`, and the Azure token endpoints is left to the operator (e.g., Windows Defender Firewall outbound rules).
- **Process sandboxing:** out of scope. This server targets developer machines, not multi-tenant hosting.
- **MCP transport security:** stdio is local — no TLS needed. If an HTTP transport is added later, it MUST bind to `127.0.0.1` only and require a per-instance shared secret.
- **Instance-count / scale-event detection:** App Service Plan instance count is not a first-class `Microsoft.Web/serverfarms` Azure Monitor metric, so scale-event detection is currently a no-op (graceful degradation). Verify the correct metric for your environment before relying on it.
