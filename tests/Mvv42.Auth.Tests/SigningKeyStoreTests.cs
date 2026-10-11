using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Mvv42.Auth.Keys;

namespace Mvv42.Auth.Tests;

public class SigningKeyStoreTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly FakeTime _time = new(new DateTimeOffset(2026, 10, 11, 12, 0, 0, TimeSpan.Zero));

    private SigningKeyStore NewStore() => new(_dir.Path, TimeSpan.FromMinutes(15), _time);

    public void Dispose() => _dir.Dispose();

    [Fact]
    public void EmptyDirectory_GeneratesKeyFile()
    {
        var key = NewStore().GetSigningKey();

        var files = Directory.GetFiles(_dir.Path, "*.pem");
        Assert.Single(files);
        Assert.Equal("es256-20261011120000.pem", Path.GetFileName(files[0]));
        Assert.Equal(new DateTimeOffset(2026, 10, 11, 12, 0, 0, TimeSpan.Zero), key.CreatedAt);
    }

    [Fact]
    public void ExistingKey_IsReloadedByNewInstance()
    {
        var first = NewStore().GetSigningKey();
        var second = NewStore().GetSigningKey();
        Assert.Equal(first.Kid, second.Kid);
    }

    [Fact]
    public void Kid_IsRfc7638Thumbprint()
    {
        var key = NewStore().GetSigningKey();

        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(key.Key));
        Assert.Equal(Base64UrlEncoder.Encode(jwk.ComputeJwkThumbprint()), key.Kid);
    }

    [Fact]
    public void NewKey_IsPublishedImmediately_ButSignsOnlyAfterActivationDelay()
    {
        var store = NewStore();
        var old = store.GetSigningKey();

        _time.Advance(TimeSpan.FromDays(30));
        var fresh = store.CreateKey();

        Assert.Equal(new[] { old.Kid, fresh.Kid }.Order(), store.GetKeys().Select(k => k.Kid).Order());
        Assert.Equal(old.Kid, store.GetSigningKey().Kid);

        _time.Advance(TimeSpan.FromMinutes(15));
        Assert.Equal(fresh.Kid, store.GetSigningKey().Kid);
    }

    [Fact]
    public void KeyDroppedIntoDirectory_IsPickedUpWithoutRestart()
    {
        var store = NewStore();
        store.GetSigningKey();

        _time.Advance(TimeSpan.FromHours(1));
        var other = NewStore().CreateKey(); // e.g. created by an operator

        _time.Advance(TimeSpan.FromMinutes(2)); // past the directory re-scan interval
        Assert.Contains(store.GetKeys(), k => k.Kid == other.Kid);
    }

    [Fact]
    public void Jwks_ContainsPublicPartsOnly()
    {
        var store = NewStore();
        var key = store.GetSigningKey();

        var jwk = Assert.Single(store.GetJwks().Keys);
        Assert.Equal("EC", jwk.Kty);
        Assert.Equal("P-256", jwk.Crv);
        Assert.Equal("ES256", jwk.Alg);
        Assert.Equal("sig", jwk.Use);
        Assert.Equal(key.Kid, jwk.Kid);
        Assert.False(string.IsNullOrEmpty(jwk.X));
        Assert.False(string.IsNullOrEmpty(jwk.Y));
    }

    private void WriteKeyFile(string name, string content) => File.WriteAllText(Path.Combine(_dir.Path, name), content);

    [Fact]
    public void Generate_WritesAtomically_LeavingNoTempFile()
    {
        NewStore().GetSigningKey();
        Assert.Equal(["es256-20261011120000.pem"], Directory.GetFiles(_dir.Path).Select(Path.GetFileName));
    }

    [Fact]
    public void LeftoverTempFile_IsIgnored()
    {
        var valid = NewStore().GetSigningKey();
        WriteKeyFile("es256-20261011130000.pem.tmp", "-----BEGIN PRIVATE KEY-----\ntruncated");

        _time.Advance(TimeSpan.FromMinutes(2));
        Assert.Equal(valid.Kid, Assert.Single(NewStore().GetKeys()).Kid);
    }

    [Fact]
    public void CorruptFile_IsSkipped_OtherKeysStillLoad()
    {
        var valid = NewStore().GetSigningKey();
        WriteKeyFile("es256-20261011110000.pem", "not a pem at all");

        var keys = NewStore().GetKeys();

        Assert.Equal(valid.Kid, Assert.Single(keys).Kid);
    }

    [Fact]
    public void OnlyCorruptFiles_AFreshKeyIsGenerated()
    {
        WriteKeyFile("es256-20261011110000.pem", "garbage");

        var key = NewStore().GetSigningKey();

        Assert.Equal("es256-20261011120000.pem", key.FileName);
    }

    [Fact]
    public void NonP256Key_IsRejected()
    {
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        WriteKeyFile("es256-20261011110000.pem", p384.ExportPkcs8PrivateKeyPem());
        var valid = NewStore().CreateKey();

        Assert.Equal(valid.Kid, Assert.Single(NewStore().GetKeys()).Kid);
    }

    [Fact]
    public void PublicOnlyKey_IsRejected()
    {
        using var publicOnly = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        WriteKeyFile("es256-20261011110000.pem", publicOnly.ExportSubjectPublicKeyInfoPem());
        var valid = NewStore().CreateKey();

        Assert.Equal(valid.Kid, Assert.Single(NewStore().GetKeys()).Kid);
    }
}
