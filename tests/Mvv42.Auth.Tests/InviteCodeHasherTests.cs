using System.Security.Cryptography;
using System.Text;
using Mvv42.Auth.Invites;
using Mvv42.Auth.Sessions;

namespace Mvv42.Auth.Tests;

/// <summary>Spec "closed registration", review decision 7: HMAC-SHA256 with a pepper file in KeysPath.</summary>
public class InviteCodeHasherTests : IDisposable
{
    private readonly TempDir _dir = new();

    private string PepperPath => Path.Combine(_dir.Path, InviteCodeHasher.PepperFileName);

    public void Dispose() => _dir.Dispose();

    [Fact]
    public void FirstStart_CreatesPepperFile_32Bytes_OwnerOnly()
    {
        _ = new InviteCodeHasher(_dir.Path);

        Assert.Equal(32, File.ReadAllBytes(PepperPath).Length);
        Assert.Equal([InviteCodeHasher.PepperFileName], Directory.GetFiles(_dir.Path).Select(Path.GetFileName));
        if (!OperatingSystem.IsWindows())
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(PepperPath));
    }

    [Fact]
    public void MissingDirectory_IsCreated()
    {
        var nested = Path.Combine(_dir.Path, "a", "b");
        _ = new InviteCodeHasher(nested);
        Assert.True(File.Exists(Path.Combine(nested, InviteCodeHasher.PepperFileName)));
    }

    [Fact]
    public void ExistingPepper_IsReused()
    {
        var first = new InviteCodeHasher(_dir.Path).Hash("ABCDEFGHJKMN");
        var second = new InviteCodeHasher(_dir.Path).Hash("ABCDEFGHJKMN");
        Assert.Equal(first, second);
    }

    [Fact]
    public void Hash_IsHmacSha256OfNormalisedCode_WithThePepper()
    {
        var pepper = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
        File.WriteAllBytes(PepperPath, pepper);

        var expected = Convert.ToHexString(HMACSHA256.HashData(pepper, Encoding.UTF8.GetBytes("ABCDEFGHJKMN"))).ToLowerInvariant();
        Assert.Equal(expected, new InviteCodeHasher(_dir.Path).Hash("ABCDEFGHJKMN"));
        Assert.NotEqual(SecretTokens.Sha256Hex("ABCDEFGHJKMN"), expected);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    [InlineData(33)]
    public void PepperOfWrongLength_StopsStartup(int length)
    {
        File.WriteAllBytes(PepperPath, new byte[length]);
        var ex = Assert.Throws<InvalidOperationException>(() => new InviteCodeHasher(_dir.Path));
        Assert.Contains(InviteCodeHasher.PepperFileName, ex.Message);
    }

    [Fact]
    public void Candidates_NewCode_OnlyHmac()
    {
        var hasher = new InviteCodeHasher(_dir.Path);
        var code = InviteCodes.Parse(" abcd-efgh-jkmn ")!;

        Assert.Equal([hasher.Hash("ABCDEFGHJKMN")], hasher.Candidates(code));
    }

    /// <summary>The legacy SHA-256 candidate only when the trimmed raw value itself looks like a legacy code.</summary>
    [Fact]
    public void Candidates_NewCodeWhoseRawLooksLegacy_HmacFirst_ThenSha256OfRaw()
    {
        var hasher = new InviteCodeHasher(_dir.Path);
        var code = InviteCodes.Parse("abcd-efgh-jkmn--------")!;

        Assert.Equal(InviteCodeKind.Normalized, code.Kind);
        Assert.Equal([hasher.Hash("ABCDEFGHJKMN"), SecretTokens.Sha256Hex("abcd-efgh-jkmn--------")], hasher.Candidates(code));
    }

    [Fact]
    public void Candidates_LegacyCode_OnlySha256OfRaw()
    {
        var hasher = new InviteCodeHasher(_dir.Path);
        var code = InviteCodes.Parse("kq3Zp9_x-AbCdEfGhIjKlMn")!;

        Assert.Equal([SecretTokens.Sha256Hex("kq3Zp9_x-AbCdEfGhIjKlMn")], hasher.Candidates(code));
    }
}
