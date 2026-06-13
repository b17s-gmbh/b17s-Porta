using b17s.Porta.Auth.Tokens;

namespace b17s.Porta.Tests.Auth.Tokens;

/// <summary>
/// Surface guard for <see cref="JwtBearerAuthOptions"/>. The JWT provider delegates validation to
/// ASP.NET Core's <c>AddJwtBearer</c> handler (see <c>AddPortaJwtAuthentication</c>), so every public
/// option on this class must be one that <c>AddJwtBearer</c> actually consumes. Options that look
/// configurable but are never read (e.g. a custom token header/prefix, or a metadata-refresh interval
/// the handler ignores) are a foot-gun: callers set them and silently get default behaviour. This
/// test fails if such an orphaned option is reintroduced, forcing a deliberate wire-up-or-drop choice.
/// </summary>
public class JwtBearerAuthOptionsTests
{
    [Fact]
    public void PublicSurface_ContainsOnlyOptionsConsumedByAddJwtBearer()
    {
        var expected = new HashSet<string>(StringComparer.Ordinal)
        {
            nameof(JwtBearerAuthOptions.Authority),
            nameof(JwtBearerAuthOptions.RequireHttpsMetadata),
            nameof(JwtBearerAuthOptions.ValidAudiences),
            nameof(JwtBearerAuthOptions.ValidIssuers),
            nameof(JwtBearerAuthOptions.ValidateIssuer),
            nameof(JwtBearerAuthOptions.ValidateAudience),
            nameof(JwtBearerAuthOptions.ValidateLifetime),
            nameof(JwtBearerAuthOptions.ClockSkew),
        };

        var actual = typeof(JwtBearerAuthOptions)
            .GetProperties()
            .Select(p => p.Name)
            .ToHashSet(StringComparer.Ordinal);

        Assert.Equal(expected, actual);
    }
}
