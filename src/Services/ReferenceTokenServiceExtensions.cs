using b17s.Porta.Auth.Tokens;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http.Resilience;

namespace b17s.Porta.Services;

/// <summary>
/// Extension methods for registering ReferenceTokenService in the DI container.
/// </summary>
public static class ReferenceTokenServiceExtensions
{
    /// <summary>
    /// Adds the ReferenceTokenService with a named, resilient HttpClient to the service collection.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configureOptions">Optional action to configure ReferenceTokenAuthOptions.</param>
    /// <param name="configureHttpClient">Optional action to configure the HttpClient.</param>
    /// <param name="configureResilience">Optional action to configure resilience policies.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddReferenceTokenService(
        this IServiceCollection services,
        Action<ReferenceTokenAuthOptions>? configureOptions = null,
        Action<HttpClient>? configureHttpClient = null,
        Action<HttpStandardResilienceOptions>? configureResilience = null)
    {
        // Configure options if provided
        if (configureOptions != null)
        {
            services.Configure(configureOptions);
        }

        // Register the named HttpClient with resilience
        var httpClientBuilder = services
            .AddHttpClient(ReferenceTokenService.HttpClientName, client =>
            {
                client.Timeout = TimeSpan.FromSeconds(30);
                client.DefaultRequestHeaders.Accept.Add(
                    new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

                configureHttpClient?.Invoke(client);
            })
            .AddStandardResilienceHandler(options =>
            {
                // Configure default resilience options
                options.AttemptTimeout.Timeout = TimeSpan.FromSeconds(10);
                options.CircuitBreaker.SamplingDuration = TimeSpan.FromSeconds(30);
                options.TotalRequestTimeout.Timeout = TimeSpan.FromSeconds(30);

                // Apply custom configuration if provided
                configureResilience?.Invoke(options);
            });

        // Register the service
        services.AddSingleton<IReferenceTokenService, ReferenceTokenService>();

        return services;
    }

    /// <summary>
    /// Adds the ReferenceTokenService with configuration from appsettings.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The configuration section containing ReferenceTokenAuthOptions.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddReferenceTokenService(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.Configure<ReferenceTokenAuthOptions>(configuration);

        return services.AddReferenceTokenService();
    }

    /// <summary>
    /// Adds the ReferenceTokenService with configuration from a named section.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The root configuration.</param>
    /// <param name="sectionName">The name of the configuration section.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddReferenceTokenService(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName)
    {
        services.Configure<ReferenceTokenAuthOptions>(configuration.GetSection(sectionName));

        return services.AddReferenceTokenService();
    }
}
