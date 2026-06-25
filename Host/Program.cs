using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using AzureIncidentInvestigator.Application.DependencyInjection;
using AzureIncidentInvestigator.Host.Charts;
using AzureIncidentInvestigator.Host.Logging;
using AzureIncidentInvestigator.Host.RateLimiting;
using AzureIncidentInvestigator.Host.Tools;
using AzureIncidentInvestigator.Infrastructure.DependencyInjection;

var builder = Host.CreateApplicationBuilder(args);

// Secrets (UptimeRobot API key) come from .NET User Secrets in local dev.
builder.Configuration.AddUserSecrets<Program>(optional: true);

// Stdio MCP transport: stdout is the JSON-RPC wire, so ALL logs must go to stderr.
builder.Services.AddSerilog((_, lc) => SerilogSetup.Configure(lc, builder.Configuration));

builder.Services.AddApplication();
builder.Services.AddInfrastructure(builder.Configuration);
builder.Services.AddSingleton<ToolRateLimiter>();
builder.Services.AddSingleton<MetricChartService>();

builder.Services
    .AddMcpServer()
    .WithStdioServerTransport()
    .WithToolsFromAssembly(typeof(InvestigationTools).Assembly);

var app = builder.Build();

try
{
    await app.RunAsync();
}
catch (Exception ex)
{
    // Last-chance handler — write to stderr only (stdout is the protocol channel).
    await Console.Error.WriteLineAsync($"MCP server terminated unexpectedly: {ex}");
    throw;
}

public partial class Program;
