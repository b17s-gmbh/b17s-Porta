using System.IO;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Serialization;

namespace b17s.Porta.Transformers;

/// <summary>
/// Supported content types for backend communication.
/// </summary>
public enum ContentType
{
    /// <summary>
    /// JSON content type (application/json). Default.
    /// </summary>
    Json,

    /// <summary>
    /// XML content type (application/xml).
    /// </summary>
    Xml,

    /// <summary>
    /// Form URL encoded content type (application/x-www-form-urlencoded).
    /// </summary>
    FormUrlEncoded
}

/// <summary>
/// Helper class for content type string conversions.
/// </summary>
public static class ContentTypes
{
    /// <summary>
    /// The JSON media type: <c>application/json</c>.
    /// </summary>
    public const string Json = "application/json";

    /// <summary>
    /// The XML media type: <c>application/xml</c>.
    /// </summary>
    public const string Xml = "application/xml";

    /// <summary>
    /// The legacy text XML media type: <c>text/xml</c>. Treated equivalently to <see cref="Xml"/>.
    /// </summary>
    public const string TextXml = "text/xml";

    /// <summary>
    /// The form URL-encoded media type: <c>application/x-www-form-urlencoded</c>.
    /// </summary>
    public const string FormUrlEncoded = "application/x-www-form-urlencoded";

    /// <summary>
    /// Gets the content type string from the enum value.
    /// </summary>
    public static string ToMediaType(this ContentType contentType) => contentType switch
    {
        ContentType.Json => Json,
        ContentType.Xml => Xml,
        ContentType.FormUrlEncoded => FormUrlEncoded,
        _ => Json
    };

    /// <summary>
    /// Parses a media type string to a ContentType enum.
    /// </summary>
    public static ContentType FromMediaType(string? mediaType)
    {
        if (string.IsNullOrEmpty(mediaType))
            return ContentType.Json;

        // Handle content type with charset (e.g., "application/json; charset=utf-8")
        var baseType = mediaType.Split(';')[0].Trim().ToLowerInvariant();

        return baseType switch
        {
            Json or "application/json" => ContentType.Json,
            Xml or TextXml or "application/xml" or "text/xml" => ContentType.Xml,
            FormUrlEncoded or "application/x-www-form-urlencoded" => ContentType.FormUrlEncoded,
            _ => ContentType.Json
        };
    }
}

/// <summary>
/// Service for serializing and deserializing content based on content type.
/// </summary>
public interface IContentSerializer
{
    /// <summary>
    /// Serializes an object to a string using the specified content type.
    /// </summary>
    string Serialize<T>(T value, ContentType contentType);

    /// <summary>
    /// Serializes an object to a string using the specified content type.
    /// </summary>
    string Serialize(object value, Type type, ContentType contentType);

    /// <summary>
    /// Deserializes a string to an object using the specified content type.
    /// </summary>
    T? Deserialize<T>(string content, ContentType contentType);

    /// <summary>
    /// Deserializes a string to an object using the specified content type.
    /// </summary>
    object? Deserialize(string content, Type type, ContentType contentType);
}

/// <summary>
/// Default implementation of content serialization supporting JSON and XML.
/// </summary>
public sealed class ContentSerializer : IContentSerializer
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    private static readonly XmlWriterSettings XmlWriterSettings = new()
    {
        Encoding = Encoding.UTF8,
        Indent = false,
        OmitXmlDeclaration = true
    };

    // Modern .NET defaults already disable DTD processing and external resolution, but pin
    // them explicitly: this file deserializes XML from untrusted backend responses, and a
    // future framework default change must not silently re-enable XXE. The entity-expansion
    // cap is pinned to the framework default of 10M characters (0 would mean *unlimited*).
    // No document-size cap is set: response bodies are already capped before they reach
    // the reader.
    private static readonly XmlReaderSettings XmlReaderSettings = new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        MaxCharactersFromEntities = 10_000_000
    };

    /// <inheritdoc/>
    public string Serialize<T>(T value, ContentType contentType) => Serialize(value!, typeof(T), contentType);

    /// <inheritdoc/>
    public string Serialize(object value, Type type, ContentType contentType)
    {
        return contentType switch
        {
            ContentType.Json => JsonSerializer.Serialize(value, type, JsonOptions),
            ContentType.Xml => SerializeXml(value, type),
            ContentType.FormUrlEncoded => SerializeFormUrlEncoded(value, type),
            _ => JsonSerializer.Serialize(value, type, JsonOptions)
        };
    }

    /// <inheritdoc/>
    public T? Deserialize<T>(string content, ContentType contentType) => (T?)Deserialize(content, typeof(T), contentType);

    /// <inheritdoc/>
    public object? Deserialize(string content, Type type, ContentType contentType)
    {
        if (string.IsNullOrWhiteSpace(content))
            return null;

        return contentType switch
        {
            ContentType.Json => JsonSerializer.Deserialize(content, type, JsonOptions),
            ContentType.Xml => DeserializeXml(content, type),
            ContentType.FormUrlEncoded => throw new NotSupportedException(
                "Form URL encoded deserialization is not supported. Use ASP.NET Core model binding instead."),
            _ => JsonSerializer.Deserialize(content, type, JsonOptions)
        };
    }

    private static string SerializeXml(object value, Type type)
    {
        var serializer = new XmlSerializer(type);
        using var stringWriter = new StringWriter();
        using var xmlWriter = XmlWriter.Create(stringWriter, XmlWriterSettings);

        // Create empty namespaces to produce cleaner XML
        var namespaces = new XmlSerializerNamespaces();
        namespaces.Add(string.Empty, string.Empty);

        serializer.Serialize(xmlWriter, value, namespaces);
        return stringWriter.ToString();
    }

    private static object? DeserializeXml(string content, Type type)
    {
        var serializer = new XmlSerializer(type);
        using var stringReader = new StringReader(content);
        using var xmlReader = XmlReader.Create(stringReader, XmlReaderSettings);
        return serializer.Deserialize(xmlReader);
    }

    private static string SerializeFormUrlEncoded(object value, Type type)
    {
        var properties = type.GetProperties();
        var pairs = new List<string>();

        foreach (var prop in properties)
        {
            var propValue = prop.GetValue(value);
            if (propValue != null)
            {
                var key = Uri.EscapeDataString(ToCamelCase(prop.Name));
                var val = Uri.EscapeDataString(propValue.ToString() ?? string.Empty);
                pairs.Add($"{key}={val}");
            }
        }

        return string.Join("&", pairs);
    }

    private static string ToCamelCase(string name)
    {
        if (string.IsNullOrEmpty(name))
            return name;
        if (name.Length == 1)
            return name.ToLowerInvariant();
        return char.ToLowerInvariant(name[0]) + name[1..];
    }
}
