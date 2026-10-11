using Mvv42.Auth.Access;
using Mvv42.Auth.Data;

namespace Mvv42.Auth.Tests;

public class AccessPolicyTests
{
    private static readonly App[] Apps =
    [
        new() { Id = "pub", Access = AppAccess.Public },
        new() { Id = "pub_anon", Access = AppAccess.Public, Anonymous = true },
        new() { Id = "inv", Access = AppAccess.Invite },
        new() { Id = "inv_anon", Access = AppAccess.Invite, Anonymous = true },
        new() { Id = "adm", Access = AppAccess.Admin },
    ];

    [Theory]
    // isAdmin, grants,          expected
    [InlineData(false, "",       "pub,pub_anon")]
    [InlineData(false, "inv",    "inv,pub,pub_anon")]
    [InlineData(false, "inv,adm", "inv,pub,pub_anon")] // a grant does not open an admin-only app
    [InlineData(true,  "",       "adm,inv,inv_anon,pub,pub_anon")]
    public void AllowedApps_Matrix(bool isAdmin, string grants, string expected)
    {
        var allowed = AccessPolicy.AllowedApps(isAdmin, Apps, grants.Split(',', StringSplitOptions.RemoveEmptyEntries));
        Assert.Equal(expected.Split(','), allowed.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void AllowedApps_IgnoresGrantsForUnknownApps()
    {
        Assert.DoesNotContain("ghost", AccessPolicy.AllowedApps(false, Apps, ["ghost"]));
    }

    [Theory]
    [InlineData(false, "", false)]
    [InlineData(true, "", true)]
    [InlineData(false, "42", true)]
    [InlineData(false, "1,42 ,7", true)]
    [InlineData(false, "1,7", false)]
    public void IsAdmin_IsDbFlagOrEnvList(bool dbFlag, string envIds, bool expected)
    {
        var user = new User { TelegramId = 42, IsAdmin = dbFlag };
        var ids = new Options.AuthOptions { AdminTelegramIds = envIds }.AdminTelegramIdSet();
        Assert.Equal(expected, AccessPolicy.IsAdmin(user, ids));
    }
}
