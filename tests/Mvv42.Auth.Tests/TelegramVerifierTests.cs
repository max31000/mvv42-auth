using System.Security.Cryptography;
using System.Text;
using Mvv42.Auth.Telegram;

namespace Mvv42.Auth.Tests;

public class TelegramVerifierTests
{
    private const string BotToken = "123456:TEST-token";
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_760_000_000);
    private readonly TelegramVerifier _verifier = new(BotToken, TimeSpan.FromHours(1), TimeSpan.FromSeconds(60));

    /// <summary>Reference implementation of the Telegram algorithm, independent of the verifier.</summary>
    internal static Dictionary<string, string> Signed(Dictionary<string, string> fields, string botToken = BotToken)
    {
        var checkString = string.Join("\n", fields.OrderBy(f => f.Key, StringComparer.Ordinal).Select(f => $"{f.Key}={f.Value}"));
        var secret = SHA256.HashData(Encoding.UTF8.GetBytes(botToken));
        var hash = Convert.ToHexString(HMACSHA256.HashData(secret, Encoding.UTF8.GetBytes(checkString))).ToLowerInvariant();
        return new Dictionary<string, string>(fields) { ["hash"] = hash };
    }

    private static Dictionary<string, string> Widget(DateTimeOffset authDate) => new()
    {
        ["id"] = "42",
        ["first_name"] = "Max",
        ["username"] = "max",
        ["auth_date"] = authDate.ToUnixTimeSeconds().ToString(),
    };

    [Fact]
    public void Valid_Signature_IsAccepted()
    {
        var result = _verifier.Verify(Signed(Widget(Now.AddMinutes(-5))), Now);
        Assert.True(result.Ok, result.Error.ToString());
    }

    [Fact]
    public void Uppercase_Hash_IsAccepted()
    {
        var fields = Signed(Widget(Now));
        fields["hash"] = fields["hash"].ToUpperInvariant();
        Assert.True(_verifier.Verify(fields, Now).Ok);
    }

    [Fact]
    public void Tampered_Field_IsRejected()
    {
        var fields = Signed(Widget(Now));
        fields["first_name"] = "Mallory";
        Assert.Equal(TelegramVerifyError.InvalidHash, _verifier.Verify(fields, Now).Error);
    }

    [Fact]
    public void Wrong_BotToken_IsRejected()
    {
        var fields = Signed(Widget(Now), botToken: "other:token");
        Assert.Equal(TelegramVerifyError.InvalidHash, _verifier.Verify(fields, Now).Error);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Missing_Or_Empty_Hash_IsMalformed(string? hash)
    {
        var fields = Widget(Now);
        if (hash is not null) fields["hash"] = hash;
        var result = _verifier.Verify(fields, Now);
        Assert.False(result.Ok);
        Assert.Equal(TelegramVerifyError.MissingHash, result.Error);
    }

    [Fact]
    public void NonHex_Hash_IsRejected()
    {
        var fields = Signed(Widget(Now));
        fields["hash"] = "zz" + fields["hash"][2..];
        Assert.Equal(TelegramVerifyError.InvalidHash, _verifier.Verify(fields, Now).Error);
    }

    [Fact]
    public void Missing_AuthDate_IsMalformed()
    {
        var fields = Widget(Now);
        fields.Remove("auth_date");
        Assert.Equal(TelegramVerifyError.MissingAuthDate, _verifier.Verify(Signed(fields), Now).Error);
    }

    [Fact]
    public void Missing_Id_IsMalformed()
    {
        var fields = Widget(Now);
        fields.Remove("id");
        Assert.Equal(TelegramVerifyError.MissingId, _verifier.Verify(Signed(fields), Now).Error);
    }

    [Fact]
    public void Stale_AuthDate_IsRejected()
    {
        var fields = Signed(Widget(Now.AddHours(-1).AddSeconds(-1)));
        Assert.Equal(TelegramVerifyError.Expired, _verifier.Verify(fields, Now).Error);
    }

    [Fact]
    public void AuthDate_AtWindowEdge_IsAccepted()
    {
        Assert.True(_verifier.Verify(Signed(Widget(Now.AddHours(-1))), Now).Ok);
    }

    [Fact]
    public void Future_AuthDate_BeyondSkew_IsRejected()
    {
        var fields = Signed(Widget(Now.AddSeconds(61)));
        Assert.Equal(TelegramVerifyError.FromFuture, _verifier.Verify(fields, Now).Error);
    }

    [Fact]
    public void Future_AuthDate_WithinSkew_IsAccepted()
    {
        Assert.True(_verifier.Verify(Signed(Widget(Now.AddSeconds(60))), Now).Ok);
    }

    [Fact]
    public void Extra_Unknown_Field_IsPartOfCheckString()
    {
        var fields = Widget(Now);
        fields["some_new_field"] = "x";
        var signed = Signed(fields);
        Assert.True(_verifier.Verify(signed, Now).Ok);

        signed.Remove("some_new_field");
        Assert.Equal(TelegramVerifyError.InvalidHash, _verifier.Verify(signed, Now).Error);
    }

    [Fact]
    public void Empty_BotToken_RejectsEverything()
    {
        var verifier = new TelegramVerifier("", TimeSpan.FromHours(1), TimeSpan.FromSeconds(60));
        Assert.Equal(TelegramVerifyError.NotConfigured, verifier.Verify(Signed(Widget(Now), botToken: ""), Now).Error);
    }
}
