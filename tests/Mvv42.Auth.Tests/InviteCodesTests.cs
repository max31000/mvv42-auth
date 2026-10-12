using System.Text.RegularExpressions;
using Mvv42.Auth.Invites;

namespace Mvv42.Auth.Tests;

/// <summary>Spec "closed registration", review decision 6: client and server normalise invite codes identically.</summary>
public class InviteCodesTests
{
    [Theory]
    [InlineData("ABCD-EFGH-JKMN", "ABCDEFGHJKMN")]
    [InlineData("  abcd efgh jkmn  ", "ABCDEFGHJKMN")]
    [InlineData("abcd-efgh-jkmn", "ABCDEFGHJKMN")]
    [InlineData("ABCDEFGHJKMN", "ABCDEFGHJKMN")]
    // Crockford: O → 0, I and L → 1
    [InlineData("OOOO-IIII-LLLL", "000011111111")]
    [InlineData("oooo-iiii-llll", "000011111111")]
    // Cyrillic look-alikes (upper and lower case) → Latin
    [InlineData("АВЕК-МНОР-СТХ0", "ABEKMH0PCTX0")]
    [InlineData("авек-мнор-стх0", "ABEKMH0PCTX0")]
    [InlineData("12 34 - 56 78 - 9ABC", "123456789ABC")]
    public void Parse_NewFormat_IsNormalised(string input, string expected)
    {
        var parsed = InviteCodes.Parse(input);

        Assert.NotNull(parsed);
        Assert.Equal(InviteCodeKind.Normalized, parsed.Kind);
        Assert.Equal(expected, parsed.Value);
        Assert.Equal(input.Trim(), parsed.Raw);
    }

    [Theory]
    [InlineData("kq3Zp9_x-AbCdEfGhIjKlMn")] // SecretTokens.New(16): 22 chars of base64url
    [InlineData("expired-code-for-status-test")]
    [InlineData("  abcdefghijklmnopqrst  ")]
    public void Parse_LegacyBase64Url_KeepsRawString(string input)
    {
        var parsed = InviteCodes.Parse(input);

        Assert.NotNull(parsed);
        Assert.Equal(InviteCodeKind.Legacy, parsed.Kind);
        Assert.Equal(input.Trim(), parsed.Value);
        Assert.Equal(input.Trim(), parsed.Raw);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("nope")]
    [InlineData("ABCD-EFGH-JKM")]      // 11 chars
    [InlineData("ABCD-EFGH-JKMNP")]    // 13 chars
    [InlineData("ABCD-EFGH-JKMU")]     // U is not in Crockford base32
    [InlineData("ABCD-EFGH-JK!N")]
    [InlineData("ДДДД-ДДДД-ДДДД")]     // Cyrillic without a Latin look-alike
    [InlineData("short_but-not20")]    // not 12 after normalisation, too short for a legacy code
    [InlineData("abcdefghijklmnopqrs!t")]
    public void Parse_Malformed_IsNull(string? input)
    {
        Assert.Null(InviteCodes.Parse(input));
    }

    [Fact]
    public void Generate_IsGroupedCrockfordBase32_AndParsesToItself()
    {
        var codes = Enumerable.Range(0, 200).Select(_ => InviteCodes.Generate()).ToList();

        Assert.All(codes, code =>
        {
            Assert.Matches(new Regex("^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$"), code);
            var parsed = InviteCodes.Parse(code);
            Assert.Equal(InviteCodeKind.Normalized, parsed!.Kind);
            Assert.Equal(code.Replace("-", ""), parsed.Value);
        });
        Assert.Equal(codes.Count, codes.Distinct().Count());
    }
}
