using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Mvv42.Auth.Keys;
using Mvv42.Auth.Options;
using Mvv42.Auth.Tokens;

namespace Mvv42.Auth.Tests;

public class AccessTokenIssuerTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly FakeTime _time = new(DateTimeOffset.UtcNow);
    private readonly SigningKeyStore _keys;
    private readonly AccessTokenIssuer _issuer;

    public AccessTokenIssuerTests()
    {
        _keys = new SigningKeyStore(_dir.Path, TimeSpan.FromMinutes(15), _time);
        _issuer = new AccessTokenIssuer(_keys, Microsoft.Extensions.Options.Options.Create(new AuthOptions()), _time);
    }

    public void Dispose() => _dir.Dispose();

    private static readonly AccessTokenSubject Subject = new(7, 42, "Max V", IsAdmin: false, Apps: ["cashpulse", "credit_calc"]);

    private TokenValidationParameters Parameters(JsonWebKeySet jwks) => new()
    {
        ValidIssuer = "https://mvv42.ru/auth",
        ValidAudience = "mvv42",
        IssuerSigningKeys = jwks.GetSigningKeys(),
        ValidAlgorithms = ["ES256"],
    };

    [Fact]
    public async Task Token_ValidatesAgainstJwks_WithExpectedClaims()
    {
        var issued = _issuer.Issue(Subject);
        var jwks = new JsonWebKeySet(JsonSerializer.Serialize(_keys.GetJwks()));

        var result = await new JsonWebTokenHandler().ValidateTokenAsync(issued.Token, Parameters(jwks));

        Assert.True(result.IsValid, result.Exception?.Message);
        var jwt = (JsonWebToken)result.SecurityToken;
        Assert.Equal("ES256", jwt.Alg);
        Assert.Equal(_keys.GetSigningKey().Kid, jwt.Kid);
        Assert.Equal("7", jwt.Subject);
        Assert.Equal("42", jwt.GetClaim("tg").Value);
        Assert.Equal("Max V", jwt.GetClaim("name").Value);
        Assert.Equal("false", jwt.GetClaim("adm").Value);
        Assert.Equal(["cashpulse", "credit_calc"], jwt.Claims.Where(c => c.Type == "apps").Select(c => c.Value));
        Assert.Equal(_time.GetUtcNow().AddMinutes(10).ToUnixTimeSeconds(), new DateTimeOffset(jwt.ValidTo).ToUnixTimeSeconds());
        Assert.Equal(issued.ExpiresAt.ToUnixTimeSeconds(), new DateTimeOffset(jwt.ValidTo).ToUnixTimeSeconds());
    }

    [Fact]
    public void AppsClaim_IsJsonArray_EvenWithSingleOrNoApp()
    {
        foreach (string[] apps in new[] { new[] { "bonds" }, Array.Empty<string>() })
        {
            var token = _issuer.Issue(Subject with { Apps = apps }).Token;
            var payload = JsonDocument.Parse(Base64UrlEncoder.Decode(token.Split('.')[1])).RootElement;
            Assert.Equal(JsonValueKind.Array, payload.GetProperty("apps").ValueKind);
            Assert.Equal(apps.Length, payload.GetProperty("apps").GetArrayLength());
        }
    }

    [Fact]
    public void AdminClaim_IsStringTrue()
    {
        var token = new JsonWebToken(_issuer.Issue(Subject with { IsAdmin = true }).Token);
        Assert.Equal("true", token.GetPayloadValue<string>("adm"));
    }

    [Fact]
    public async Task Token_FromOtherKey_IsRejected()
    {
        using var otherDir = new TempDir();
        var other = new SigningKeyStore(otherDir.Path, TimeSpan.FromMinutes(15), _time);
        var jwks = new JsonWebKeySet(JsonSerializer.Serialize(other.GetJwks()));

        var result = await new JsonWebTokenHandler().ValidateTokenAsync(_issuer.Issue(Subject).Token, Parameters(jwks));

        Assert.False(result.IsValid);
    }
}

public class JwksEndpointTests(AuthAppFactory factory) : IClassFixture<AuthAppFactory>
{
    [Fact]
    public async Task Jwks_IsServedUnderPathBase()
    {
        var response = await factory.CreateClient().GetAsync("/auth/.well-known/jwks.json");
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        var key = Assert.Single(body.GetProperty("keys").EnumerateArray());
        Assert.Equal("EC", key.GetProperty("kty").GetString());
        Assert.False(key.TryGetProperty("d", out _));
        Assert.Contains("max-age", response.Headers.CacheControl?.ToString());
    }
}
