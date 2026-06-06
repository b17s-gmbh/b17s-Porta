using System.Text.Json;

using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace b17s.Porta.Auth.Sessions;

/// <summary>
/// Session-based token storage with optional encryption via Data Protection.
/// </summary>
public sealed class SessionTokenStorage(
    ILogger<SessionTokenStorage> logger,
    IDataProtectionProvider? dataProtectionProvider = null) : ITokenStorage
{
    private readonly IDataProtector? _protector = dataProtectionProvider?.CreateProtector("Porta.SessionTokens.v1");

    public Task<string?> GetTokenAsync(HttpContext context, string key)
    {
        try
        {
            var storedValue = context.Session.GetString(key);
            if (string.IsNullOrEmpty(storedValue))
                return Task.FromResult<string?>(null);

            if (_protector != null)
            {
                try
                {
                    return Task.FromResult<string?>(_protector.Unprotect(storedValue));
                }
                catch (Exception ex)
                {
                    logger.DecryptionFailed(key, ex);
                    return Task.FromResult<string?>(null);
                }
            }

            return Task.FromResult<string?>(storedValue);
        }
        catch (Exception ex)
        {
            logger.StorageError("get", key, ex);
            return Task.FromResult<string?>(null);
        }
    }

    public Task<bool> SetTokenAsync(HttpContext context, string key, string value)
    {
        try
        {
            var storedValue = _protector != null ? _protector.Protect(value) : value;
            context.Session.SetString(key, storedValue);
            return Task.FromResult(true);
        }
        catch (Exception ex)
        {
            logger.StorageError("set", key, ex);
            return Task.FromResult(false);
        }
    }

    public Task RemoveTokenAsync(HttpContext context, string key)
    {
        try
        {
            context.Session.Remove(key);
        }
        catch (Exception ex)
        {
            logger.StorageError("remove", key, ex);
        }
        return Task.CompletedTask;
    }

    public Task<T?> GetObjectAsync<T>(HttpContext context, string key) where T : class
    {
        try
        {
            var storedValue = context.Session.GetString(key);
            if (string.IsNullOrEmpty(storedValue))
                return Task.FromResult<T?>(null);

            string json;
            if (_protector != null)
            {
                try
                {
                    json = _protector.Unprotect(storedValue);
                }
                catch (Exception ex)
                {
                    logger.DecryptionFailed(key, ex);
                    return Task.FromResult<T?>(null);
                }
            }
            else
            {
                json = storedValue;
            }

            return Task.FromResult(JsonSerializer.Deserialize<T>(json));
        }
        catch (Exception ex)
        {
            logger.StorageError("get object", key, ex);
            return Task.FromResult<T?>(null);
        }
    }

    public Task<bool> SetObjectAsync<T>(HttpContext context, string key, T value) where T : class
    {
        try
        {
            var json = JsonSerializer.Serialize(value);
            var storedValue = _protector != null ? _protector.Protect(json) : json;
            context.Session.SetString(key, storedValue);
            return Task.FromResult(true);
        }
        catch (Exception ex)
        {
            logger.StorageError("set object", key, ex);
            return Task.FromResult(false);
        }
    }

    public Task RemoveObjectAsync(HttpContext context, string key)
        => RemoveTokenAsync(context, key);

    public Task<bool> ClearAllAsync(HttpContext context)
    {
        try
        {
            context.Session.Clear();
            return Task.FromResult(true);
        }
        catch (Exception ex)
        {
            logger.StorageError("clear", "all", ex);
            return Task.FromResult(false);
        }
    }
}

/// <summary>
/// High-performance logging for SessionTokenStorage.
/// </summary>
internal static partial class SessionTokenStorageLogging
{
    [LoggerMessage(EventId = 13900, Level = LogLevel.Error,
        Message = "Failed to decrypt token for key {Key}")]
    public static partial void DecryptionFailed(this ILogger logger, string key, Exception ex);

    [LoggerMessage(EventId = 13901, Level = LogLevel.Error,
        Message = "Session storage {Operation} failed for key {Key}")]
    public static partial void StorageError(this ILogger logger, string operation, string key, Exception ex);
}
