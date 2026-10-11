using System.Globalization;
using System.Text.Json;

namespace Mvv42.Auth.Telegram;

/// <summary>Telegram profile extracted from verified widget fields.</summary>
public sealed record TelegramProfile(long TelegramId, string FirstName, string? LastName, string? Username, string? PhotoUrl);

public static class TelegramAuthData
{
    /// <summary>
    /// Converts the raw widget object to string fields for verification. Only fields actually present
    /// are kept (nulls are dropped — the widget never sends them); numbers keep their raw JSON text, booleans
    /// become <c>"true"</c>/<c>"false"</c> (how Telegram puts them into the data-check-string).
    /// Returns null when the body is not a flat JSON object.
    /// </summary>
    public static Dictionary<string, string>? ToFields(JsonElement body)
    {
        if (body.ValueKind != JsonValueKind.Object)
            return null;

        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var property in body.EnumerateObject())
        {
            switch (property.Value.ValueKind)
            {
                case JsonValueKind.Null:
                    continue;
                case JsonValueKind.String:
                    fields[property.Name] = property.Value.GetString()!;
                    break;
                case JsonValueKind.Number:
                    fields[property.Name] = property.Value.GetRawText();
                    break;
                case JsonValueKind.True:
                    fields[property.Name] = "true";
                    break;
                case JsonValueKind.False:
                    fields[property.Name] = "false";
                    break;
                default:
                    return null;
            }
        }
        return fields;
    }

    /// <summary>Profile from verified fields (call only after a successful verification).</summary>
    public static TelegramProfile ToProfile(IReadOnlyDictionary<string, string> fields) => new(
        long.Parse(fields["id"], CultureInfo.InvariantCulture),
        fields.GetValueOrDefault("first_name") ?? "",
        fields.GetValueOrDefault("last_name"),
        fields.GetValueOrDefault("username"),
        fields.GetValueOrDefault("photo_url"));
}
