using System.Text.Json;
using System.Text.Json.Serialization;

namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Response from OAuth2 token introspection endpoint (RFC 7662)
/// </summary>
public sealed class IntrospectionResponse
{
    /// <summary>
    /// Whether the token is currently active
    /// </summary>
    [JsonPropertyName("active")]
    public bool Active { get; set; }

    /// <summary>
    /// Scope values for the token
    /// </summary>
    [JsonPropertyName("scope")]
    public string? Scope { get; set; }

    /// <summary>
    /// Client identifier
    /// </summary>
    [JsonPropertyName("client_id")]
    public string? ClientId { get; set; }

    /// <summary>
    /// Username of the resource owner
    /// </summary>
    [JsonPropertyName("username")]
    public string? Username { get; set; }

    /// <summary>
    /// Token type (e.g., "Bearer")
    /// </summary>
    [JsonPropertyName("token_type")]
    public string? TokenType { get; set; }

    /// <summary>
    /// Expiration time (Unix timestamp)
    /// </summary>
    [JsonPropertyName("exp")]
    public long? Exp { get; set; }

    /// <summary>
    /// Issued at time (Unix timestamp)
    /// </summary>
    [JsonPropertyName("iat")]
    public long? Iat { get; set; }

    /// <summary>
    /// Not before time (Unix timestamp)
    /// </summary>
    [JsonPropertyName("nbf")]
    public long? Nbf { get; set; }

    /// <summary>
    /// Subject identifier
    /// </summary>
    [JsonPropertyName("sub")]
    public string? Sub { get; set; }

    /// <summary>
    /// Audience(s). RFC 7519 / RFC 7662 allow either a single string or an array of strings.
    /// </summary>
    [JsonPropertyName("aud")]
    [JsonConverter(typeof(StringOrStringArrayConverter))]
    public string[]? Aud { get; set; }

    /// <summary>
    /// Issuer
    /// </summary>
    [JsonPropertyName("iss")]
    public string? Iss { get; set; }

    /// <summary>
    /// JWT ID
    /// </summary>
    [JsonPropertyName("jti")]
    public string? Jti { get; set; }

    /// <summary>
    /// Additional custom claims returned by the introspection endpoint
    /// </summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalClaims { get; set; }
}

/// <summary>
/// Deserializes a JSON value that may be either a string or an array of strings into <c>string[]?</c>.
/// Required because RFC 7519 §4.1.3 permits <c>aud</c> in either form, and RFC 7662 inherits that.
/// </summary>
internal sealed class StringOrStringArrayConverter : JsonConverter<string[]?>
{
    public override string[]? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.Null:
                return null;
            case JsonTokenType.String:
                {
                    var value = reader.GetString();
                    return value is null ? null : [value];
                }
            case JsonTokenType.StartArray:
                {
                    var values = new List<string>();
                    while (reader.Read())
                    {
                        if (reader.TokenType == JsonTokenType.EndArray)
                            return values.ToArray();
                        if (reader.TokenType != JsonTokenType.String)
                            throw new JsonException("Expected string element in array.");
                        var value = reader.GetString();
                        if (value is not null)
                            values.Add(value);
                    }
                    throw new JsonException("Unterminated array.");
                }
            default:
                throw new JsonException($"Unexpected token {reader.TokenType} for string-or-array.");
        }
    }

    public override void Write(Utf8JsonWriter writer, string[]? value, JsonSerializerOptions options)
    {
        if (value is null)
        {
            writer.WriteNullValue();
            return;
        }
        if (value.Length == 1)
        {
            writer.WriteStringValue(value[0]);
            return;
        }
        writer.WriteStartArray();
        foreach (var v in value)
            writer.WriteStringValue(v);
        writer.WriteEndArray();
    }
}
