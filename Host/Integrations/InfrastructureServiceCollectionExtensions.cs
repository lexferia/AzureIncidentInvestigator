using Azure.Core;
using Azure.Monitor.Query;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AzureIncidentInvestigator;

public static class InfrastructureServiceCollectionExtensions
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<UptimeRobotOptions>(configuration.GetSection(UptimeRobotOptions.SectionName));
        services.Configure<AppInsightsOptions>(configuration.GetSection(AppInsightsOptions.SectionName));
        services.Configure<AppServicePlansOptions>(configuration.GetSection(AppServicePlansOptions.SectionName));
        services.Configure<AppServiceSitesOptions>(configuration.GetSection(AppServiceSitesOptions.SectionName));
        services.Configure<DatabasesOptions>(configuration.GetSection(DatabasesOptions.SectionName));
        services.Configure<ReportsOptions>(configuration.GetSection(ReportsOptions.SectionName));
        services.Configure<RateLimitOptions>(configuration.GetSection(RateLimitOptions.SectionName));

        services.AddMemoryCache();
        services.AddTransient<UptimeRobotAuthHandler>();

        var uptimeRobotOptions = configuration.GetSection(UptimeRobotOptions.SectionName).Get<UptimeRobotOptions>() ?? new UptimeRobotOptions();

        services.AddHttpClient<IUptimeRobotClient, UptimeRobotClient>(http =>
            {
                http.BaseAddress = new Uri(uptimeRobotOptions.BaseUrl);
                http.Timeout = TimeSpan.FromSeconds(uptimeRobotOptions.TimeoutSeconds);
            })
            .AddHttpMessageHandler<UptimeRobotAuthHandler>()
            .AddStandardResilienceHandler();

        services.AddSingleton<TokenCredential>(_ => AzureCredentialFactory.Create());
        services.AddSingleton(sp => new LogsQueryClient(sp.GetRequiredService<TokenCredential>()));
        services.AddSingleton(sp => new MetricsQueryClient(sp.GetRequiredService<TokenCredential>()));

        services.AddSingleton<AppInsightsQueryService>();
        services.AddSingleton<AppServicePlanMetricsService>();
        services.AddSingleton<AppServiceSiteHealthService>();
        services.AddSingleton<DatabaseHealthService>();

        services.AddTransient<AzureManagementAuthHandler>();
        services.AddHttpClient<AppServiceDetectorService>(http =>
            {
                http.BaseAddress = new Uri("https://management.azure.com/");
                http.Timeout = TimeSpan.FromSeconds(30);
            })
            .AddHttpMessageHandler<AzureManagementAuthHandler>();

        return services;
    }
}
