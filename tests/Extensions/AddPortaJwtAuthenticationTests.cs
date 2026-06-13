using b17s.Porta.Auth.Tokens;
using b17s.Porta.Extensions;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Extensions;

/// <summary>
/// M6 regression: AddPortaJwtAuthentication used to invoke the consumer lambda twice and
/// wire the JwtBearer handler from a registration-time snapshot, so external
/// Configure/PostConfigure&lt;JwtBearerAuthOptions&gt; was silently ignored by the actual
/// handler. The handler must bind from the composed options pipeline.
/// </summary>
public class AddPortaJwtAuthenticationTests
{
    [Fact]
    public void BindsConfiguredValuesOntoTheJwtBearerHandler()
    {
        var services = CreateServices();
        services.AddPortaJwtAuthentication(o =>
        {
            o.Authority = "https://idp.example.com";
            o.ValidAudiences = ["my-porta"];
        });

        var sp = services.BuildServiceProvider();
        var jwt = sp.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        Assert.Equal("https://idp.example.com", jwt.Authority);
        Assert.True(jwt.SaveToken);
        Assert.Contains("my-porta", jwt.TokenValidationParameters.ValidAudiences);
    }

    [Fact]
    public void PostConfigure_ReachesTheJwtBearerHandler()
    {
        var services = CreateServices();
        services.AddPortaJwtAuthentication(o => o.Authority = "https://placeholder.example.com");

        // Late composition, e.g. injecting the real value from a secret store.
        services.PostConfigure<JwtBearerAuthOptions>(o => o.Authority = "https://real-idp.example.com");

        var sp = services.BuildServiceProvider();
        var jwt = sp.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        Assert.Equal("https://real-idp.example.com", jwt.Authority);
    }

    [Fact]
    public void ConsumerLambda_IsInvokedOnce_AtOptionsBuildTime()
    {
        var invocations = 0;

        var services = CreateServices();
        services.AddPortaJwtAuthentication(o =>
        {
            invocations++;
            o.Authority = "https://idp.example.com";
        });

        // Registration must not eagerly invoke the lambda (the old snapshot did,
        // firing side effects like secret fetches twice).
        Assert.Equal(0, invocations);

        var sp = services.BuildServiceProvider();
        _ = sp.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        Assert.Equal(1, invocations);
    }

    private static ServiceCollection CreateServices()
    {
        var services = new ServiceCollection();
        services.AddOptions();
        services.AddLogging();
        return services;
    }
}
