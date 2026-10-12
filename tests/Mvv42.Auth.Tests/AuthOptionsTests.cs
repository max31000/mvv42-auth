using Mvv42.Auth.Options;

namespace Mvv42.Auth.Tests;

public class AuthOptionsTests
{
    [Fact]
    public void AdminTelegramIds_ParsedOnce_SeparatorsTolerated()
    {
        var options = new AuthOptions { AdminTelegramIds = " 1000, 2000;3000 " };

        var first = options.AdminTelegramIdSet();

        Assert.Equal([1000L, 2000L, 3000L], first.Order());
        Assert.Same(first, options.AdminTelegramIdSet());
    }

    [Theory]
    [InlineData("abc")]
    [InlineData("1000,12x")]
    [InlineData("-5")]
    [InlineData("0")]
    [InlineData("99999999999999999999")]
    public void AdminTelegramIds_Malformed_Throws(string value)
    {
        var ex = Assert.Throws<FormatException>(() => new AuthOptions { AdminTelegramIds = value }.AdminTelegramIdSet());
        Assert.Contains("Auth:AdminTelegramIds", ex.Message);
    }

    [Fact]
    public void TrustedProxyCidrs_ParsesIpsAndNetworks()
    {
        var networks = new AuthOptions { TrustedProxyCidrs = "172.18.0.1, 10.0.0.0/8 ,fd00::/8" }.TrustedProxyNetworks();

        Assert.Equal(["172.18.0.1/32", "10.0.0.0/8", "fd00::/8"], networks.Select(n => $"{n.Prefix}/{n.PrefixLength}"));
    }

    [Theory]
    [InlineData("172.18.0.1/33")]
    [InlineData("not-an-ip")]
    [InlineData("10.0.0.0/x")]
    public void TrustedProxyCidrs_Malformed_Throws(string value)
    {
        var ex = Assert.Throws<FormatException>(() => new AuthOptions { TrustedProxyCidrs = value }.TrustedProxyNetworks());
        Assert.Contains("Auth:TrustedProxyCidrs", ex.Message);
    }

    [Fact]
    public void Registration_DefaultsToInvite()
    {
        Assert.Equal(RegistrationMode.Invite, new AuthOptions().GetRegistrationMode());
    }

    [Theory]
    [InlineData("invite", RegistrationMode.Invite)]
    [InlineData("open", RegistrationMode.Open)]
    [InlineData(" Open ", RegistrationMode.Open)]
    public void Registration_Parsed(string value, RegistrationMode expected)
    {
        Assert.Equal(expected, new AuthOptions { Registration = value }.GetRegistrationMode());
    }

    [Theory]
    [InlineData("")]
    [InlineData("closed")]
    [InlineData("invites")]
    public void Registration_Unknown_Throws(string value)
    {
        var ex = Assert.Throws<FormatException>(() => new AuthOptions { Registration = value }.GetRegistrationMode());
        Assert.Contains("Auth:Registration", ex.Message);
    }

    [Fact]
    public void StartupWarnings_InviteWithoutOwners_Warns()
    {
        Assert.Contains(new AuthOptions { Registration = "invite", AdminTelegramIds = "" }.StartupWarnings(),
            w => w.Contains("Auth:AdminTelegramIds"));
        Assert.Empty(new AuthOptions { Registration = "invite", AdminTelegramIds = "1000" }.StartupWarnings());
        Assert.Empty(new AuthOptions { Registration = "open", AdminTelegramIds = "" }.StartupWarnings());
    }
}
