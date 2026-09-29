namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Thrown by <see cref="ClientCredentialsTokenService"/> when the request's own configuration is
/// unusable (e.g. an unreadable or invalid <c>private_key_jwt</c> key, or no client id), as opposed
/// to the token endpoint rejecting the request. Lets callers classify it as an operator
/// misconfiguration rather than an authentication failure; the ClientCredentials backend-auth
/// handler translates it to a <see cref="b17s.Porta.Transformers.BackendAuthConfigurationException"/>.
/// </summary>
internal sealed class ClientCredentialsConfigurationException(string message, Exception? innerException = null)
    : InvalidOperationException(message, innerException);
