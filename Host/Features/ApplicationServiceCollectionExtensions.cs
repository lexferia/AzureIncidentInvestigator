using Microsoft.Extensions.DependencyInjection;

namespace AzureIncidentInvestigator;

public static class ApplicationServiceCollectionExtensions
{
    public static IServiceCollection AddApplication(this IServiceCollection services)
    {
        services.AddSingleton<ITextRedactor, TextRedactor>();
        services.AddSingleton<CrawlerClassifier>();
        services.AddSingleton<ToolInputValidator>();
        services.AddSingleton<IncidentService>();
        services.AddSingleton<CrawlerDetectionService>();
        services.AddSingleton<ReportGenerationService>();
        return services;
    }
}
