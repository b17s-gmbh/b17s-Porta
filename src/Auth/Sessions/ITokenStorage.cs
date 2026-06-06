using Microsoft.AspNetCore.Http;

namespace b17s.Porta.Auth.Sessions;

/// <summary>
/// Abstraction for token storage to decouple authentication providers from session-based storage
/// </summary>
public interface ITokenStorage
{
    /// <summary>
    /// Retrieves a token value by key
    /// </summary>
    Task<string?> GetTokenAsync(HttpContext context, string key);

    /// <summary>
    /// Stores a token value with a key
    /// </summary>
    /// <returns>True if successful, false if failed</returns>
    Task<bool> SetTokenAsync(HttpContext context, string key, string value);

    /// <summary>
    /// Removes a token by key
    /// </summary>
    Task RemoveTokenAsync(HttpContext context, string key);

    /// <summary>
    /// Retrieves a complex object (for API token caching, etc.)
    /// </summary>
    Task<T?> GetObjectAsync<T>(HttpContext context, string key) where T : class;

    /// <summary>
    /// Stores a complex object
    /// </summary>
    /// <returns>True if successful, false if failed</returns>
    Task<bool> SetObjectAsync<T>(HttpContext context, string key, T value) where T : class;

    /// <summary>
    /// Removes an object by key
    /// </summary>
    Task RemoveObjectAsync(HttpContext context, string key);

    /// <summary>
    /// Clears all tokens for the current context
    /// </summary>
    /// <returns>True if successful, false if failed</returns>
    Task<bool> ClearAllAsync(HttpContext context);
}
