using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.IdentityModel.Tokens;

namespace Mvv42.Auth.Keys;

public sealed record SigningKey(string Kid, ECDsa Key, DateTimeOffset CreatedAt, string FileName)
{
    public ECDsaSecurityKey SecurityKey { get; } = new(Key) { KeyId = Kid };
}

public sealed record Jwk(
    [property: JsonPropertyName("kty")] string Kty,
    [property: JsonPropertyName("crv")] string Crv,
    [property: JsonPropertyName("x")] string X,
    [property: JsonPropertyName("y")] string Y,
    [property: JsonPropertyName("kid")] string Kid,
    [property: JsonPropertyName("alg")] string Alg,
    [property: JsonPropertyName("use")] string Use);

public sealed record JwksDocument([property: JsonPropertyName("keys")] IReadOnlyList<Jwk> Keys);

/// <summary>
/// ES256 keys stored as PEM files <c>es256-yyyyMMddHHmmss.pem</c> (UTC creation time) in <c>KeysPath</c>.
/// All keys are published in JWKS. The signing key is the newest one that is older than the activation
/// delay (so caches of every consumer already know it); a lone key signs immediately.
/// The directory is re-scanned every minute, so an operator can drop a new key in without a restart.
/// </summary>
public sealed class SigningKeyStore(string keysPath, TimeSpan activationDelay, TimeProvider time)
{
    private const string Prefix = "es256-";
    private const string TimestampFormat = "yyyyMMddHHmmss";
    private static readonly TimeSpan RescanInterval = TimeSpan.FromMinutes(1);

    private readonly object _lock = new();
    private IReadOnlyList<SigningKey> _keys = [];
    private DateTimeOffset _loadedAt = DateTimeOffset.MinValue;

    public IReadOnlyList<SigningKey> GetKeys()
    {
        lock (_lock)
        {
            var now = time.GetUtcNow();
            if (_keys.Count == 0 || now - _loadedAt >= RescanInterval)
            {
                _keys = LoadFromDisk();
                if (_keys.Count == 0)
                    _keys = [Generate(now)];
                _loadedAt = now;
            }
            return _keys;
        }
    }

    public SigningKey GetSigningKey()
    {
        var keys = GetKeys(); // ordered newest first
        var activeBefore = time.GetUtcNow() - activationDelay;
        return keys.FirstOrDefault(k => k.CreatedAt <= activeBefore) ?? keys[^1];
    }

    /// <summary>Creates a new key file (rotation). It is published at once and starts signing after the activation delay.</summary>
    public SigningKey CreateKey()
    {
        lock (_lock)
        {
            var key = Generate(time.GetUtcNow());
            _keys = LoadFromDisk();
            _loadedAt = time.GetUtcNow();
            return key;
        }
    }

    public JwksDocument GetJwks() => new(GetKeys().Select(ToJwk).ToList());

    /// <summary>RFC 7638 JWK thumbprint (SHA-256, base64url) of an EC P-256 public key.</summary>
    public static string ComputeThumbprint(ECParameters p)
    {
        var canonical = $$"""{"crv":"P-256","kty":"EC","x":"{{Base64UrlEncoder.Encode(p.Q.X)}}","y":"{{Base64UrlEncoder.Encode(p.Q.Y)}}"}""";
        return Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    private static Jwk ToJwk(SigningKey key)
    {
        var p = key.Key.ExportParameters(includePrivateParameters: false);
        return new Jwk("EC", "P-256", Base64UrlEncoder.Encode(p.Q.X), Base64UrlEncoder.Encode(p.Q.Y), key.Kid, "ES256", "sig");
    }

    private List<SigningKey> LoadFromDisk()
    {
        if (!Directory.Exists(keysPath))
            return [];

        // Unchanged files keep their already loaded key objects (and the crypto providers cached for them).
        var known = _keys.ToDictionary(k => k.FileName, StringComparer.Ordinal);
        return Directory.GetFiles(keysPath, Prefix + "*.pem")
            .Select(path => known.GetValueOrDefault(Path.GetFileName(path)) ?? Load(path))
            .OrderByDescending(k => k.CreatedAt)
            .ThenByDescending(k => k.FileName, StringComparer.Ordinal)
            .ToList();
    }

    private static SigningKey Load(string path)
    {
        var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(File.ReadAllText(path));
        var stem = Path.GetFileNameWithoutExtension(path);
        var createdAt = DateTimeOffset.TryParseExact(stem[Prefix.Length..], TimestampFormat, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
            ? parsed
            : new DateTimeOffset(File.GetLastWriteTimeUtc(path), TimeSpan.Zero);
        var kid = ComputeThumbprint(ecdsa.ExportParameters(includePrivateParameters: false));
        return new SigningKey(kid, ecdsa, createdAt, Path.GetFileName(path));
    }

    private SigningKey Generate(DateTimeOffset now)
    {
        Directory.CreateDirectory(keysPath);
        var createdAt = new DateTimeOffset(now.Year, now.Month, now.Day, now.Hour, now.Minute, now.Second, TimeSpan.Zero);
        string path;
        while (File.Exists(path = Path.Combine(keysPath, Prefix + createdAt.ToString(TimestampFormat, CultureInfo.InvariantCulture) + ".pem")))
            createdAt = createdAt.AddSeconds(1);

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows())
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        using (var writer = new StreamWriter(path, Encoding.ASCII, options))
            writer.Write(ecdsa.ExportPkcs8PrivateKeyPem());

        return Load(path);
    }
}
