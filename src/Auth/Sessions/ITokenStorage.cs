using Microsoft.AspNetCore.Http;

namespace b17s.Porta.Auth.Sessions;

/// <summary>
/// Abstraction for token storage to decouple authentication providers from session-based storage
/// </summary>
public interface ITokenStorage
{
    /// <summary>
    /// Retrieves a token value by key.
    /// </summary>
    /// <param name="context">The HTTP context the token is scoped to.</param>
    /// <param name="key">The key the token was stored under.</param>
    /// <returns>The stored token value, or <see langword="null"/> if no token exists for the key.</returns>
    Task<string?> GetTokenAsync(HttpContext context, string key);

    /// <summary>
    /// Stores a token value with a key.
    /// </summary>
    /// <param name="context">The HTTP context the token is scoped to.</param>
    /// <param name="key">The key to store the token under.</param>
    /// <param name="value">The token value to store.</param>
    /// <returns><see langword="true"/> if successful; <see langword="false"/> if storage failed.</returns>
    Task<bool> SetTokenAsync(HttpContext context, string key, string value);

    /// <summary>
    /// Removes a token by key.
    /// </summary>
    /// <param name="context">The HTTP context the token is scoped to.</param>
    /// <param name="key">The key of the token to remove.</param>
    Task RemoveTokenAsync(HttpContext context, string key);

    /// <summary>
    /// Retrieves a complex object (for API token caching, etc.).
    /// </summary>
    /// <typeparam name="T">The reference type the stored object deserializes to.</typeparam>
    /// <param name="context">The HTTP context the object is scoped to.</param>
    /// <param name="key">The key the object was stored under.</param>
    /// <returns>The stored object, or <see langword="null"/> if no object exists for the key.</returns>
    Task<T?> GetObjectAsync<T>(HttpContext context, string key) where T : class;

    /// <summary>
    /// Stores a complex object.
    /// </summary>
    /// <typeparam name="T">The reference type of the object to store.</typeparam>
    /// <param name="context">The HTTP context the object is scoped to.</param>
    /// <param name="key">The key to store the object under.</param>
    /// <param name="value">The object to store.</param>
    /// <returns><see langword="true"/> if successful; <see langword="false"/> if storage failed.</returns>
    Task<bool> SetObjectAsync<T>(HttpContext context, string key, T value) where T : class;

    /// <summary>
    /// Removes an object by key.
    /// </summary>
    /// <param name="context">The HTTP context the object is scoped to.</param>
    /// <param name="key">The key of the object to remove.</param>
    Task RemoveObjectAsync(HttpContext context, string key);

    /// <summary>
    /// Clears all tokens for the current context.
    /// </summary>
    /// <param name="context">The HTTP context whose tokens should be cleared.</param>
    /// <returns><see langword="true"/> if successful; <see langword="false"/> if the operation failed.</returns>
    Task<bool> ClearAllAsync(HttpContext context);
}
