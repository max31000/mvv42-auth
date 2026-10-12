using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Mvv42.Auth.Invites;

public enum InviteCodeKind
{
    /// <summary>New format: 12 Crockford base32 characters, <see cref="InviteCode.Value"/> is the normalised form.</summary>
    Normalized,

    /// <summary>Old base64url code (<c>SecretTokens.New(16)</c>): <see cref="InviteCode.Value"/> is the raw string.</summary>
    Legacy,
}

/// <param name="Value">What the new-format hash is computed from (normalised code, or the raw legacy code).</param>
/// <param name="Raw">The trimmed input: its SHA-256 is how codes created before the closed registration were stored.</param>
public sealed record InviteCode(InviteCodeKind Kind, string Value, string Raw);

/// <summary>
/// Invite code format and normalisation (spec "closed registration", review decision 6 — the shell does the same):
/// trim → Cyrillic look-alikes to Latin → upper case → drop whitespace and hyphens → Crockford (O→0, I/L→1) →
/// must match <c>^[0-9A-HJKMNP-TV-Z]{12}$</c>. Otherwise a string that looks like an old base64url code
/// (<c>^[A-Za-z0-9_-]{20,}$</c>) is used as is; anything else is malformed.
/// </summary>
public static partial class InviteCodes
{
    /// <summary>Crockford base32 (no I, L, O, U).</summary>
    public const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    public const int Length = 12;

    [GeneratedRegex("^[0-9A-HJKMNP-TV-Z]{12}$")]
    private static partial Regex NormalizedPattern();

    [GeneratedRegex("^[A-Za-z0-9_-]{20,}$")]
    private static partial Regex LegacyPattern();

    private static readonly Dictionary<char, char> Lookalikes = new()
    {
        ['А'] = 'A',
        ['В'] = 'B',
        ['Е'] = 'E',
        ['К'] = 'K',
        ['М'] = 'M',
        ['Н'] = 'H',
        ['О'] = 'O',
        ['Р'] = 'P',
        ['С'] = 'C',
        ['Т'] = 'T',
        ['Х'] = 'X',
    };

    /// <summary>A new code, displayed as <c>XXXX-XXXX-XXXX</c> (60 random bits).</summary>
    public static string Generate()
    {
        var chars = new char[Length + 2];
        for (int i = 0, j = 0; i < Length; i++)
        {
            if (i is 4 or 8)
                chars[j++] = '-';
            chars[j++] = Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)];
        }
        return new string(chars);
    }

    /// <summary>The normalised code, the raw legacy code, or null when the input is neither.</summary>
    public static InviteCode? Parse(string? input)
    {
        var raw = input?.Trim();
        if (string.IsNullOrEmpty(raw))
            return null;

        var normalized = new StringBuilder(raw.Length);
        foreach (var c in raw.ToUpperInvariant())
        {
            if (char.IsWhiteSpace(c) || c == '-')
                continue;
            var latin = Lookalikes.GetValueOrDefault(c, c);
            normalized.Append(latin switch
            {
                'O' => '0',
                'I' or 'L' => '1',
                _ => latin,
            });
        }

        var value = normalized.ToString();
        if (NormalizedPattern().IsMatch(value))
            return new InviteCode(InviteCodeKind.Normalized, value, raw);
        return LegacyPattern().IsMatch(raw) ? new InviteCode(InviteCodeKind.Legacy, raw, raw) : null;
    }
}
