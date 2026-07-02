using Microsoft.Extensions.DependencyInjection;
using AzureIncidentInvestigator.Application.Abstractions;
using AzureIncidentInvestigator.Application.Crawlers;
using AzureIncidentInvestigator.Application.Incidents;
using AzureIncidentInvestigator.Application.Redaction;
using AzureIncidentInvestigator.Application.Reports;
using AzureIncidentInvestigator.Application.Validation;

namespace AzureIncidentInvestigator.Application.DependencyInjection;

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
