using System.Net;
using Mvv42.Auth.Http;

namespace Mvv42.Auth.Tests;

public class ClientIpTests
{
    [Theory]
    [InlineData("::ffff:203.0.113.9", "203.0.113.9")]
    [InlineData("::ffff:127.0.0.1", "127.0.0.1")]
    [InlineData("203.0.113.9", "203.0.113.9")]
    [InlineData("2001:db8::1", "2001:db8::1")]
    [InlineData("::1", "::1")]
    public void Normalize_MapsIPv4MappedIPv6ToIPv4(string raw, string expected) =>
        Assert.Equal(expected, ClientIp.Normalize(IPAddress.Parse(raw)));

    [Fact]
    public void Normalize_Null_IsNull() => Assert.Null(ClientIp.Normalize(null));
}
