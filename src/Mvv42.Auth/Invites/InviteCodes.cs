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
/// Invite code format and normalisation, identical to the shell (spec "closed registration", review decision 6; shared
/// vectors in <c>portalShell/src/invite/code-vectors.json</c>, asserted in the tests): trim (explicit whitespace set) →
/// per character: drop whitespace and dashes, Cyrillic look-alikes → Latin upper case, ASCII a–z → A–Z (no culture or
/// full Unicode case mapping), Crockford O→0, I/L→1 → must match <c>^[0-9A-HJKMNP-TV-Z]{12}$</c>. Otherwise a trimmed
/// input that looks like an old base64url code (<c>^[A-Za-z0-9_-]{20,}$</c>) is used as is; anything else is malformed.
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

    /// <summary>Cyrillic letters that look like Latin ones (upper and lower case) → Latin upper case.</summary>
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
        ['а'] = 'A',
        ['в'] = 'B',
        ['е'] = 'E',
        ['к'] = 'K',
        ['м'] = 'M',
        ['н'] = 'H',
        ['о'] = 'O',
        ['р'] = 'P',
        ['с'] = 'C',
        ['т'] = 'T',
        ['х'] = 'X',
    };

    /// <summary>
    /// Space, tab, CR, LF, NBSP, U+2000–U+200B (en quad … zero-width space), narrow NBSP, medium math space,
    /// ideographic space, BOM: trimmed at the ends and dropped inside.
    /// </summary>
    private static bool IsWhitespace(char c) =>
        c is ' ' or '\t' or '\n' or '\r' or '\u00A0' or (>= '\u2000' and <= '\u200B') or '\u202F' or '\u205F' or '\u3000' or '\uFEFF';

    /// <summary>Hyphen-minus, U+2010–U+2015 (hyphen … horizontal bar), U+2212 minus: dropped inside.</summary>
    private static bool IsDash(char c) => c is '-' or (>= '\u2010' and <= '\u2015') or '\u2212';

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

    /// <summary>The trimmed input looks like a code issued before the closed registration (stored as its SHA-256).</summary>
    public static bool LooksLegacy(string raw) => LegacyPattern().IsMatch(raw);

    /// <summary>The normalised code, the raw legacy code, or null when the input is neither.</summary>
    public static InviteCode? Parse(string? input)
    {
        if (input is null)
            return null;
        int start = 0, end = input.Length;
        while (start < end && IsWhitespace(input[start]))
            start++;
        while (end > start && IsWhitespace(input[end - 1]))
            end--;
        var raw = input[start..end];
        if (raw.Length == 0)
            return null;

        var normalized = new StringBuilder(raw.Length);
        foreach (var c in raw)
        {
            if (IsWhitespace(c) || IsDash(c))
                continue;
            var upper = Lookalikes.TryGetValue(c, out var latin) ? latin : c is >= 'a' and <= 'z' ? (char)(c - 0x20) : c;
            normalized.Append(upper switch
            {
                'O' => '0',
                'I' or 'L' => '1',
                _ => upper,
            });
        }

        var value = normalized.ToString();
        if (NormalizedPattern().IsMatch(value))
            return new InviteCode(InviteCodeKind.Normalized, value, raw);
        return LooksLegacy(raw) ? new InviteCode(InviteCodeKind.Legacy, raw, raw) : null;
    }
}
