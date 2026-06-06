using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Extensions;

/// <summary>
/// Emits startup diagnostics when the BFF auth pipeline is wired without
/// the prerequisites for a multi-instance deployment, and enforces
/// secure-by-default Data Protection key encryption at rest.
/// <list type="bullet">
///   <item>Warns when no shared <see cref="Microsoft.Extensions.Caching.Distributed.IDistributedCache"/>
///   (Redis/Valkey) is registered.</item>
///   <item>Warns when shared Data Protection key persistence is not configured.</item>
///   <item>Throws (in non-Development environments) when Data Protection persistence is configured
///   but neither a key-encryption callback was supplied nor
///   <see cref="DataProtectionExtensions.AcknowledgeUnencryptedDataProtectionKeys"/> was called.
///   Warns instead in Development so dev loops are not broken.</item>
///   <item>Throws (in non-Development environments) when a key-encryption callback <em>was</em>
///   supplied but registered no <see cref="Microsoft.AspNetCore.DataProtection.XmlEncryption.IXmlEncryptor"/>
///   (e.g. an empty <c>dp =&gt; { }</c> lambda) - the attestation is hollow and keys still
///   persist in plaintext. Verified by resolving the effective
///   <see cref="KeyManagementOptions"/> after the container is built. Warns instead in Development.</item>
///   <item>Throws (in non-Development environments) when a distributed cache is registered
///   but the in-process refresh lock was registered explicitly and not acknowledged via
///   <see cref="RefreshLockExtensions.AcknowledgeInProcessRefreshLock"/>. Warns instead in
///   Development.</item>
/// </list>
/// Single-instance dev/test deployments are unaffected by the warnings - they are informational.
/// </summary>
internal sealed class HaConfigurationStartupCheck(
    ILogger<HaConfigurationStartupCheck> logger,
    IHostEnvironment environment,
    IServiceProvider services,
    bool distributedCacheConfigured,
    bool dataProtectionPersistenceConfigured,
    bool dataProtectionKeysEncryptionAttested,
    bool dataProtectionKeysEncryptionAcknowledged,
    bool distributedRefreshLockConfiguredOrAcknowledged) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (!distributedCacheConfigured)
        {
            logger.DistributedCacheMissing();
        }

        if (!dataProtectionPersistenceConfigured)
        {
            logger.DataProtectionPersistenceMissing();
        }
        else if (dataProtectionKeysEncryptionAcknowledged)
        {
            // Operator explicitly opted into unencrypted keys (dev / single-box with
            // full-disk encryption). Nothing to verify - the choice is reviewable at
            // the call site via the recorded reason.
        }
        else if (!dataProtectionKeysEncryptionAttested)
        {
            // Persistence is on but the operator did not promise key encryption at rest
            // (no protectKeys action passed, no AcknowledgeUnencryptedDataProtectionKeys call).
            // In a real environment that's a credential-equivalent leak waiting to happen -
            // anyone who reads the keys table/blob can decrypt every active session.
            if (environment.IsDevelopment())
            {
                logger.DataProtectionKeysUnencryptedDevelopment();
            }
            else
            {
                logger.DataProtectionKeysUnencryptedFatal();
                throw new InvalidOperationException(
                    "Porta: Data Protection key persistence is configured without key encryption at rest. " +
                    "Pass a protectKeys action that calls a ProtectKeysWith… extension " +
                    "(certificate, Azure Key Vault, AWS KMS, DPAPI) to AddPortaDataProtectionWithEntityFrameworkStore " +
                    "or AddPortaDataProtectionPersistence. For local dev or a single-box deployment with full-disk " +
                    "encryption, call services.AcknowledgeUnencryptedDataProtectionKeys(reason: \"…\") to opt out " +
                    "explicitly. See docs/ha-deployment.md.");
            }
        }
        else if (!IsKeyEncryptorRegistered())
        {
            // A protectKeys action was supplied (attestation present) but, now that the
            // container is built and the effective KeyManagementOptions are bound, no
            // IXmlEncryptor was actually registered - e.g. an empty `dp => { }` lambda
            // that never called a ProtectKeysWith… extension. The attestation is hollow:
            // keys still persist in plaintext, same blast radius as no encryption at all.
            if (environment.IsDevelopment())
            {
                logger.DataProtectionKeysAttestationHollowDevelopment();
            }
            else
            {
                logger.DataProtectionKeysAttestationHollowFatal();
                throw new InvalidOperationException(
                    "Porta: a Data Protection protectKeys action was supplied but registered no IXmlEncryptor, " +
                    "so keys are still persisted in plaintext. Ensure the action calls a ProtectKeysWith… extension " +
                    "(certificate, Azure Key Vault, AWS KMS, DPAPI) on the supplied IDataProtectionBuilder. For local " +
                    "dev or a single-box deployment with full-disk encryption, call " +
                    "services.AcknowledgeUnencryptedDataProtectionKeys(reason: \"…\") to opt out explicitly. " +
                    "See docs/ha-deployment.md.");
            }
        }

        if (!distributedRefreshLockConfiguredOrAcknowledged)
        {
            // Distributed cache is registered (multi-replica intent) but the consumer
            // explicitly registered the in-process RefreshLockRegistry without an
            // acknowledgement. With a strict-rotation IdP, cross-replica refresh
            // races will cause spurious sign-outs.
            if (environment.IsDevelopment())
            {
                logger.InProcessRefreshLockOnHaDeploymentDevelopment();
            }
            else
            {
                logger.InProcessRefreshLockOnHaDeploymentFatal();
                throw new InvalidOperationException(
                    "Porta: a distributed cache is registered (suggesting a multi-replica deployment) but " +
                    "the in-process RefreshLockRegistry was registered explicitly. With a strict-rotation " +
                    "IdP, cross-replica refresh races will cause spurious sign-outs. Either omit the " +
                    "explicit registration so the IDistributedCache-backed lock is auto-picked, register " +
                    "your own distributed IRefreshLock implementation, or call " +
                    "services.AcknowledgeInProcessRefreshLock(reason: \"…\") if this is genuinely a " +
                    "single-box deployment that uses a remote cache for other reasons. " +
                    "See docs/ha-deployment.md.");
            }
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>
    /// Best-effort verification that a key encryptor is actually wired. Resolving
    /// <see cref="IOptions{KeyManagementOptions}"/> runs every <c>IConfigureOptions</c>
    /// (including the one a <c>ProtectKeysWith…</c> extension registers), so
    /// <see cref="KeyManagementOptions.XmlEncryptor"/> reflects the effective configuration
    /// rather than the registration-time attestation marker.
    /// </summary>
    private bool IsKeyEncryptorRegistered() =>
        services.GetService<IOptions<KeyManagementOptions>>()?.Value.XmlEncryptor is not null;
}

internal static partial class HaConfigurationStartupCheckLogging
{
    [LoggerMessage(EventId = 14500, Level = LogLevel.Warning,
        Message = "Porta: no IDistributedCache registered before AddPortaAuthentication; " +
                  "falling back to in-memory cache. This is fine for single-instance dev. " +
                  "For HA (>1 replica) register Redis/Valkey first " +
                  "(services.AddStackExchangeRedisCache(...) or builder.AddRedisDistributedCache(\"cache\")). " +
                  "See docs/ha-deployment.md.")]
    public static partial void DistributedCacheMissing(this ILogger logger);

    [LoggerMessage(EventId = 14501, Level = LogLevel.Warning,
        Message = "Porta: Data Protection key persistence is not configured. Each replica will " +
                  "generate its own key ring at startup, so cookies/tickets minted on one instance " +
                  "will fail to decrypt on another and OIDC sign-in will fail without sticky sessions. " +
                  "Call services.AddPortaDataProtectionWithEntityFrameworkStore(...) or " +
                  "AddPortaDataProtectionPersistence(dp => dp.PersistKeysTo...) before AddPortaAuthentication. " +
                  "See docs/ha-deployment.md.")]
    public static partial void DataProtectionPersistenceMissing(this ILogger logger);

    [LoggerMessage(EventId = 14502, Level = LogLevel.Warning,
        Message = "Porta: Data Protection keys are persisted without encryption at rest. " +
                  "This is permitted in Development; in Production it would be fatal. " +
                  "Before deploying, pass a protectKeys action that calls a ProtectKeysWith… extension " +
                  "(certificate, Azure Key Vault, AWS KMS, DPAPI), or call " +
                  "services.AcknowledgeUnencryptedDataProtectionKeys(reason: \"…\") to opt out explicitly. " +
                  "See docs/ha-deployment.md.")]
    public static partial void DataProtectionKeysUnencryptedDevelopment(this ILogger logger);

    [LoggerMessage(EventId = 14503, Level = LogLevel.Critical,
        Message = "Porta: Data Protection keys are persisted without encryption at rest and no explicit " +
                  "acknowledgement was registered. Refusing to start - anyone with read access to the " +
                  "key store could decrypt every active session. See docs/ha-deployment.md.")]
    public static partial void DataProtectionKeysUnencryptedFatal(this ILogger logger);

    [LoggerMessage(EventId = 14506, Level = LogLevel.Warning,
        Message = "Porta: a Data Protection protectKeys action was supplied but registered no IXmlEncryptor " +
                  "(e.g. an empty lambda), so keys are still persisted in plaintext. This is permitted in " +
                  "Development; in Production it would be fatal. Ensure the action calls a ProtectKeysWith… " +
                  "extension (certificate, Azure Key Vault, AWS KMS, DPAPI), or call " +
                  "services.AcknowledgeUnencryptedDataProtectionKeys(reason: \"…\") to opt out explicitly. " +
                  "See docs/ha-deployment.md.")]
    public static partial void DataProtectionKeysAttestationHollowDevelopment(this ILogger logger);

    [LoggerMessage(EventId = 14507, Level = LogLevel.Critical,
        Message = "Porta: a Data Protection protectKeys action was supplied but registered no IXmlEncryptor, " +
                  "so keys are still persisted in plaintext. Refusing to start - anyone with read access to the " +
                  "key store could decrypt every active session. Ensure the action calls a ProtectKeysWith… " +
                  "extension on the supplied IDataProtectionBuilder. See docs/ha-deployment.md.")]
    public static partial void DataProtectionKeysAttestationHollowFatal(this ILogger logger);

    [LoggerMessage(EventId = 14504, Level = LogLevel.Warning,
        Message = "Porta: a distributed cache is registered but the in-process RefreshLockRegistry was " +
                  "registered explicitly. This is permitted in Development; in non-Development it would " +
                  "be a startup failure. On a multi-replica deployment with a strict-rotation IdP this " +
                  "produces spurious sign-outs. Either omit the explicit registration (the library will " +
                  "auto-pick the IDistributedCache-backed lock), register your own distributed IRefreshLock, " +
                  "or call services.AcknowledgeInProcessRefreshLock(reason: \"…\"). See docs/ha-deployment.md.")]
    public static partial void InProcessRefreshLockOnHaDeploymentDevelopment(this ILogger logger);

    [LoggerMessage(EventId = 14505, Level = LogLevel.Critical,
        Message = "Porta: a distributed cache is registered but the in-process RefreshLockRegistry was " +
                  "registered explicitly and no acknowledgement was provided. Refusing to start - on a " +
                  "multi-replica deployment with a strict-rotation IdP, cross-replica refresh races will " +
                  "cause spurious sign-outs. See docs/ha-deployment.md.")]
    public static partial void InProcessRefreshLockOnHaDeploymentFatal(this ILogger logger);
}
