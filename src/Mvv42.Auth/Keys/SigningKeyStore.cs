using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging.Abstractions;
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
/// A file that cannot be used (unreadable, not PEM, not a P-256 private key) is logged and skipped.
/// </summary>
public sealed class SigningKeyStore(string keysPath, TimeSpan activationDelay, TimeProvider time, ILogger? logger = null)
{
    private const string P256Oid = "1.2.840.10045.3.1.7";

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
            .Where(path => string.Equals(Path.GetExtension(path), ".pem", StringComparison.Ordinal))
            .Select(path => known.GetValueOrDefault(Path.GetFileName(path)) ?? TryLoad(path))
            .OfType<SigningKey>()
            .OrderByDescending(k => k.CreatedAt)
            .ThenByDescending(k => k.FileName, StringComparer.Ordinal)
            .ToList();
    }

    private SigningKey? TryLoad(string path)
    {
        try
        {
            return Load(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException
                                       or CryptographicException or InvalidDataException)
        {
            (logger ?? NullLogger.Instance).LogError(ex, "Skipping signing key file {File}: {Reason}", Path.GetFileName(path), ex.Message);
            return null;
        }
    }

    private static SigningKey Load(string path)
    {
        var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportFromPem(File.ReadAllText(path));

            // ES256 only: a P-384/P-521 key would produce tokens nobody accepts (and a wrong "crv" in JWKS).
            var publicParameters = ecdsa.ExportParameters(includePrivateParameters: false);
            if (!publicParameters.Curve.IsNamed || publicParameters.Curve.Oid.Value != P256Oid)
                throw new InvalidDataException($"not a P-256 key (curve {publicParameters.Curve.Oid.FriendlyName ?? publicParameters.Curve.Oid.Value})");

            // A public-only PEM imports fine but cannot sign.
            try
            {
                ecdsa.ExportParameters(includePrivateParameters: true);
            }
            catch (CryptographicException)
            {
                throw new InvalidDataException("public key only, a private key is required");
            }
        }
        catch
        {
            ecdsa.Dispose();
            throw;
        }

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

        // Atomic: write *.pem.tmp (not matched by the *.pem scan), then rename, so a crash or a concurrent scan
        // never sees a half-written key file.
        var tmp = path + ".tmp";
        var options = new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows())
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        using (var writer = new StreamWriter(tmp, Encoding.ASCII, options))
        {
            writer.Write(ecdsa.ExportPkcs8PrivateKeyPem());
            writer.Flush();
            ((FileStream)writer.BaseStream).Flush(flushToDisk: true);
        }
        File.Move(tmp, path, overwrite: false);

        return Load(path);
    }
}
