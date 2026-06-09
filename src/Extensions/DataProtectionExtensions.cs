using b17s.Porta.Data;

using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace b17s.Porta.Extensions;

/// <summary>
/// Extension methods for configuring ASP.NET Data Protection key persistence
/// for HA deployments.
///
/// In multi-instance deployments, every replica must protect/unprotect data
/// (auth tickets, OIDC correlation cookies, encrypted refresh tokens) with the
/// same key ring. Without shared persistence each instance generates its own
/// keys at startup and cookies/tickets minted by one replica fail to decrypt
/// on another.
///
/// The library does not pick a backend automatically because it doesn't know
/// which database or cache the consuming app uses. Call one of these helpers
/// before <see cref="AuthenticationServiceExtensions.AddPortaAuthentication(IServiceCollection, Microsoft.Extensions.Configuration.IConfiguration, string)"/>
/// to mark persistence as configured (suppressing the HA warning) and wire
/// the chosen backend.
///
/// Persisted keys must also be encrypted at rest. Anyone who can read the key
/// store (DB row, Redis hash, blob) can otherwise decrypt every session ticket
/// and refresh token the BFF has ever minted. Both helpers split persistence
/// from encryption: <c>persist</c> wires the storage backend, <c>protectKeys</c>
/// wires the key encryptor (certificate, Key Vault, KMS, DPAPI). For local
/// development on a single machine, opt out of encryption explicitly with
/// <see cref="AcknowledgeUnencryptedDataProtectionKeys"/> - otherwise
/// <see cref="AuthenticationServiceExtensions.AddPortaAuthentication(IServiceCollection, Microsoft.Extensions.Configuration.IConfiguration, string)"/> refuses
/// to start in non-Development environments.
///
/// See docs/ha-deployment.md for the full picture.
/// </summary>
public static class DataProtectionExtensions
{
    /// <summary>
    /// Marker registration that records the consuming app has explicitly
    /// configured Data Protection persistence. Reads are exposed via
    /// <see cref="IsConfigured"/>.
    /// </summary>
    private sealed class PortaDataProtectionPersistenceMarker;

    /// <summary>
    /// Marker registration that records the consuming app has supplied a
    /// key-encryption (<c>ProtectKeysWith…</c>) action to one of the
    /// <c>AddPortaDataProtection*</c> helpers. The marker is the operator's
    /// registration-time attestation; the startup check verifies it is not hollow
    /// by confirming an <c>IXmlEncryptor</c> is present on the effective
    /// <c>KeyManagementOptions</c> once the container is built.
    /// </summary>
    private sealed class PortaDataProtectionKeysEncryptionAttestationMarker;

    /// <summary>
    /// Marker registration that records the consuming app has explicitly
    /// acknowledged that Data Protection keys will be persisted unencrypted.
    /// Used to suppress the secure-by-default startup throw on dev machines
    /// or single-box deployments with full-disk encryption.
    /// </summary>
    private sealed record PortaUnencryptedDataProtectionAcknowledgement(string Reason);

    /// <summary>
    /// Registers <see cref="DataProtectionDbContext"/> against <paramref name="optionsAction"/>,
    /// persists the Data Protection key ring to it, and applies <paramref name="protectKeys"/>
    /// for encryption at rest. Use this when you already run a relational database
    /// (PostgreSQL, SQL Server, ...) and want the keys to live alongside other
    /// application data.
    ///
    /// <paramref name="protectKeys"/> must call a <c>ProtectKeysWith…</c> extension on the
    /// supplied <see cref="IDataProtectionBuilder"/>. Without key encryption at rest, anyone
    /// with read access to the <c>DataProtectionKeys</c> table can decrypt every cookie ticket
    /// and refresh token the BFF has minted. For dev / single-box use, call
    /// <see cref="AcknowledgeUnencryptedDataProtectionKeys"/> in addition (or instead, paired
    /// with the open hook) so the choice is reviewable in the call site.
    /// </summary>
    /// <example>
    /// <code>
    /// builder.Services.AddPortaDataProtectionWithEntityFrameworkStore(
    ///     opts => opts.UseNpgsql(builder.Configuration.GetConnectionString("Keys")),
    ///     dp => dp.ProtectKeysWithCertificate(cert));
    /// builder.Services.AddPortaAuthentication(builder.Configuration);
    /// </code>
    /// </example>
    public static IServiceCollection AddPortaDataProtectionWithEntityFrameworkStore(
        this IServiceCollection services,
        Action<DbContextOptionsBuilder> optionsAction,
        Action<IDataProtectionBuilder> protectKeys,
        string tableName = DataProtectionDbContextOptions.DefaultTableName,
        string? schema = null)
    {
        ArgumentNullException.ThrowIfNull(optionsAction);
        ArgumentNullException.ThrowIfNull(protectKeys);
        ArgumentException.ThrowIfNullOrWhiteSpace(tableName);

        // Bind the table/schema before the DbContext is registered so OnModelCreating
        // picks them up via IOptions<DataProtectionDbContextOptions>. Defaulting to
        // "DataProtectionKeys" with no schema keeps existing deployments wire-
        // compatible; override these in shared/multi-tenant DBs to avoid colliding
        // with other apps that store DP keys.
        services.Configure<DataProtectionDbContextOptions>(opt =>
        {
            opt.TableName = tableName;
            opt.Schema = schema;
        });

        services.AddDbContext<DataProtectionDbContext>(optionsAction);
        var dp = services.AddDataProtection().PersistKeysToDbContext<DataProtectionDbContext>();
        protectKeys(dp);
        services.AddSingleton<PortaDataProtectionPersistenceMarker>();
        services.AddSingleton<PortaDataProtectionKeysEncryptionAttestationMarker>();

        return services;
    }

    /// <summary>
    /// Hook for configuring Data Protection persistence with a backend the library
    /// doesn't bundle (Redis, Azure Blob Storage, AWS S3, file system on a shared
    /// mount, etc.).
    ///
    /// <paramref name="persist"/> receives the same <see cref="IDataProtectionBuilder"/>
    /// you would get from <c>services.AddDataProtection()</c>; call its persistence
    /// extension method (<c>PersistKeysToStackExchangeRedis</c>,
    /// <c>PersistKeysToAzureBlobStorage</c>, ...).
    ///
    /// <paramref name="protectKeys"/> receives the same builder and must call a
    /// <c>ProtectKeysWith…</c> extension (<c>ProtectKeysWithCertificate</c>,
    /// <c>ProtectKeysWithAzureKeyVault</c>, <c>ProtectKeysWithAwsKms</c>,
    /// <c>ProtectKeysWithDpapi</c>, ...). For dev / single-box use, pass <c>null</c>
    /// and call <see cref="AcknowledgeUnencryptedDataProtectionKeys"/> separately.
    /// </summary>
    /// <example>
    /// <code>
    /// var redis = ConnectionMultiplexer.Connect(builder.Configuration["Redis:ConnectionString"]!);
    /// builder.Services.AddPortaDataProtectionPersistence(
    ///     persist: dp => dp.PersistKeysToStackExchangeRedis(redis, "DataProtection-Keys"),
    ///     protectKeys: dp => dp.ProtectKeysWithAzureKeyVault(
    ///         new Uri(builder.Configuration["KeyVault:KeyId"]!), credential));
    /// builder.Services.AddPortaAuthentication(builder.Configuration);
    /// </code>
    /// </example>
    public static IServiceCollection AddPortaDataProtectionPersistence(
        this IServiceCollection services,
        Action<IDataProtectionBuilder> persist,
        Action<IDataProtectionBuilder>? protectKeys)
    {
        ArgumentNullException.ThrowIfNull(persist);

        var dp = services.AddDataProtection();
        persist(dp);
        if (protectKeys is not null)
        {
            protectKeys(dp);
            services.AddSingleton<PortaDataProtectionKeysEncryptionAttestationMarker>();
        }
        services.AddSingleton<PortaDataProtectionPersistenceMarker>();

        return services;
    }

    /// <summary>
    /// Acknowledges that Data Protection keys will be persisted without encryption at rest,
    /// suppressing the secure-by-default startup throw. Use only for local development on a
    /// single machine, or single-box production deployments where full-disk encryption and
    /// strict file-system permissions are the operator's chosen defense.
    ///
    /// In a multi-instance deployment, unencrypted persisted keys mean a database/cache read
    /// is enough to decrypt every active session - pass a real <c>protectKeys</c> action to
    /// one of the <c>AddPortaDataProtection*</c> helpers instead.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="reason">A human-readable justification recorded with the acknowledgement
    /// (e.g. <c>"local dev"</c>, <c>"single VM, encrypted disk"</c>). Required so the choice
    /// is reviewable in the call site rather than silent.</param>
    public static IServiceCollection AcknowledgeUnencryptedDataProtectionKeys(
        this IServiceCollection services,
        string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        services.AddSingleton(new PortaUnencryptedDataProtectionAcknowledgement(reason));
        return services;
    }

    /// <summary>
    /// Returns <c>true</c> if one of the <c>AddPortaDataProtection*</c> helpers has been
    /// called. Resolved from the built container at boot, so the helper may be called
    /// before or after <c>AddPortaAuthentication</c>. Used by the startup HA check.
    /// </summary>
    internal static bool IsConfigured(IServiceProvider services) =>
        services.GetService<PortaDataProtectionPersistenceMarker>() is not null;

    /// <summary>
    /// Returns <c>true</c> if a <c>protectKeys</c> action was supplied to one of the
    /// <c>AddPortaDataProtection*</c> helpers. This is the operator's attestation
    /// only; the startup check (<see cref="HaConfigurationStartupCheck"/>) additionally
    /// verifies the action actually registered an <c>IXmlEncryptor</c> once the effective
    /// <c>KeyManagementOptions</c> are bound, catching a hollow (empty-lambda) attestation.
    /// </summary>
    internal static bool IsKeysEncryptionAttested(IServiceProvider services) =>
        services.GetService<PortaDataProtectionKeysEncryptionAttestationMarker>() is not null;

    /// <summary>
    /// Returns <c>true</c> if <see cref="AcknowledgeUnencryptedDataProtectionKeys"/> has been
    /// called. Used by the startup security check to allow dev / single-box opt-out from
    /// key-encryption-at-rest enforcement.
    /// </summary>
    internal static bool IsUnencryptedAcknowledged(IServiceProvider services) =>
        services.GetService<PortaUnencryptedDataProtectionAcknowledgement>() is not null;
}
