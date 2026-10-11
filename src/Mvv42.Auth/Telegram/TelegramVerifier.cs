using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Mvv42.Auth.Telegram;

public enum TelegramVerifyError
{
    None,
    NotConfigured,
    MissingHash,
    MissingAuthDate,
    MissingId,
    InvalidHash,
    Expired,
    FromFuture,
}

public readonly record struct TelegramVerifyResult(TelegramVerifyError Error)
{
    public bool Ok => Error == TelegramVerifyError.None;

    /// <summary>Malformed request (400) as opposed to a failed check (401).</summary>
    public bool IsMalformed => Error is TelegramVerifyError.MissingHash
        or TelegramVerifyError.MissingAuthDate or TelegramVerifyError.MissingId;
}

/// <summary>
/// Telegram Login Widget check (https://core.telegram.org/widgets/login#checking-authorization):
/// data-check-string = every field the widget sent except <c>hash</c>, sorted by key, <c>key=value</c> joined by '\n';
/// hash = hex(HMAC-SHA256(key: SHA256(botToken), data-check-string)).
/// </summary>
public sealed class TelegramVerifier(string botToken, TimeSpan authDateWindow, TimeSpan futureSkew)
{
    public TelegramVerifyResult Verify(IReadOnlyDictionary<string, string> fields, DateTimeOffset now)
    {
        if (string.IsNullOrEmpty(botToken))
            return new(TelegramVerifyError.NotConfigured);

        if (!fields.TryGetValue("hash", out var hash) || string.IsNullOrWhiteSpace(hash))
            return new(TelegramVerifyError.MissingHash);
        if (!fields.TryGetValue("auth_date", out var authDateRaw)
            || !long.TryParse(authDateRaw, NumberStyles.None, CultureInfo.InvariantCulture, out var authDateUnix))
            return new(TelegramVerifyError.MissingAuthDate);
        if (!fields.TryGetValue("id", out var id) || !long.TryParse(id, NumberStyles.None, CultureInfo.InvariantCulture, out _))
            return new(TelegramVerifyError.MissingId);

        var checkString = string.Join("\n", fields
            .Where(f => f.Key != "hash")
            .OrderBy(f => f.Key, StringComparer.Ordinal)
            .Select(f => $"{f.Key}={f.Value}"));

        var secret = SHA256.HashData(Encoding.UTF8.GetBytes(botToken));
        var expected = HMACSHA256.HashData(secret, Encoding.UTF8.GetBytes(checkString));

        byte[] actual;
        try
        {
            actual = Convert.FromHexString(hash.Trim());
        }
        catch (FormatException)
        {
            return new(TelegramVerifyError.InvalidHash);
        }

        // FixedTimeEquals returns false for different lengths without leaking timing of the content.
        if (!CryptographicOperations.FixedTimeEquals(expected, actual))
            return new(TelegramVerifyError.InvalidHash);

        var authDate = DateTimeOffset.FromUnixTimeSeconds(authDateUnix);
        if (authDate > now + futureSkew)
            return new(TelegramVerifyError.FromFuture);
        if (now - authDate > authDateWindow)
            return new(TelegramVerifyError.Expired);

        return new(TelegramVerifyError.None);
    }
}
