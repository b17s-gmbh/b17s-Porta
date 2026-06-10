using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace b17s.Porta.Configuration;

/// <summary>
/// Forwards change notifications from every <see cref="OidcAuthOptions"/> change-token
/// source (e.g. the configuration section bound by
/// <c>AddPortaOidcAuth(IConfiguration)</c>) to
/// <see cref="SessionAuthenticationConfiguration"/>. The session configuration is a
/// projection of the composed <see cref="OidcAuthOptions"/>, so without this bridge an
/// <c>IOptionsMonitor&lt;SessionAuthenticationConfiguration&gt;</c> consumer would keep
/// the boot-time projection across configuration reloads.
/// </summary>
internal sealed class OidcAuthChangeTokenForwarder(
    IEnumerable<IOptionsChangeTokenSource<OidcAuthOptions>> sources)
    : IOptionsChangeTokenSource<SessionAuthenticationConfiguration>
{
    public string Name => Options.DefaultName;

    public IChangeToken GetChangeToken()
        => new CompositeChangeToken([.. sources.Select(s => s.GetChangeToken())]);
}
