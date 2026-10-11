using System.Text.Json;
using Mvv42.Auth.Telegram;

namespace Mvv42.Auth.Tests;

public class TelegramAuthDataTests
{
    private static JsonElement Json(string json) => JsonDocument.Parse(json).RootElement;

    [Fact]
    public void ToFields_KeepsSentFields_DropsNulls_NumbersRaw()
    {
        var fields = TelegramAuthData.ToFields(Json("""{"id":42,"first_name":"Max","last_name":null,"auth_date":1760000000,"hash":"ab"}"""));

        Assert.NotNull(fields);
        Assert.Equal(["auth_date", "first_name", "hash", "id"], fields.Keys.Order());
        Assert.Equal("42", fields["id"]);
        Assert.Equal("1760000000", fields["auth_date"]);
    }

    [Theory]
    [InlineData("""{"id":{"x":1}}""")]
    [InlineData("""{"id":[1]}""")]
    [InlineData("""[1,2]""")]
    public void ToFields_RejectsNonFlatObjects(string json)
    {
        Assert.Null(TelegramAuthData.ToFields(Json(json)));
    }

    [Fact]
    public void ToFields_JsonBooleans_BecomeTrueFalseStrings()
    {
        // The widget may send e.g. "allows_write_to_pm": true; Telegram signs it as the string "true".
        var fields = TelegramAuthData.ToFields(Json("""{"id":42,"allows_write_to_pm":true,"x":false}"""));

        Assert.NotNull(fields);
        Assert.Equal("true", fields["allows_write_to_pm"]);
        Assert.Equal("false", fields["x"]);
    }

    [Fact]
    public void ToProfile_MapsOptionalFields()
    {
        var profile = TelegramAuthData.ToProfile(new Dictionary<string, string>
        {
            ["id"] = "42",
            ["first_name"] = "Max",
            ["photo_url"] = "https://t.me/p.jpg",
        });
        Assert.Equal(new TelegramProfile(42, "Max", null, null, "https://t.me/p.jpg"), profile);
    }
}
