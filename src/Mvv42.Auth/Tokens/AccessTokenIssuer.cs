using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Mvv42.Auth.Keys;
using Mvv42.Auth.Options;

namespace Mvv42.Auth.Tokens;

/// <summary>What goes into an access token.</summary>
public sealed record AccessTokenSubject(long UserId, long TelegramId, string Name, bool IsAdmin, IReadOnlyCollection<string> Apps);

public sealed record IssuedAccessToken(string Token, DateTimeOffset ExpiresAt);

/// <summary>Issues ES256 access JWTs: sub, tg, name, adm ("true"/"false"), apps (JSON array); kid in header.</summary>
public sealed class AccessTokenIssuer(SigningKeyStore keys, IOptions<AuthOptions> options, TimeProvider time)
{
    private static readonly JsonWebTokenHandler Handler = new() { SetDefaultTimesOnTokenCreation = false };

    public IssuedAccessToken Issue(AccessTokenSubject subject)
    {
        var o = options.Value;
        var now = time.GetUtcNow();
        var expires = now + o.AccessTokenLifetime;
        var key = keys.GetSigningKey();

        var token = Handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = o.Issuer,
            Audience = o.Audience,
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = expires.UtcDateTime,
            SigningCredentials = new SigningCredentials(key.SecurityKey, SecurityAlgorithms.EcdsaSha256),
            Claims = new Dictionary<string, object>
            {
                [JwtRegisteredClaimNames.Sub] = subject.UserId.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["tg"] = subject.TelegramId.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["name"] = subject.Name,
                ["adm"] = subject.IsAdmin ? "true" : "false",
                ["apps"] = subject.Apps.ToList(),
            },
        });

        return new IssuedAccessToken(token, expires);
    }

    /// <summary>Validation parameters for tokens issued by this service (used for its own cookie auth).</summary>
    public static TokenValidationParameters ValidationParameters(AuthOptions o, SigningKeyStore keys) => new()
    {
        ValidIssuer = o.Issuer,
        ValidAudience = o.Audience,
        ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
        IssuerSigningKeyResolver = (_, _, _, _) => keys.GetKeys().Select(k => (SecurityKey)k.SecurityKey),
        ClockSkew = TimeSpan.FromSeconds(30),
        NameClaimType = "name",
    };
}
