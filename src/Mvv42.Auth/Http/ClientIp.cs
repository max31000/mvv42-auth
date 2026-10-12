using System.Net;

namespace Mvv42.Auth.Http;

/// <summary>
/// Client IP as stored in <c>sessions.ip</c> / <c>login_events.ip</c>: <c>Connection.RemoteIpAddress</c> after
/// ForwardedHeaders (nginx passes the real client IP), IPv4-mapped IPv6 (<c>::ffff:1.2.3.4</c>) shown as IPv4.
/// </summary>
public static class ClientIp
{
    public static string? Normalize(IPAddress? address) => address switch
    {
        null => null,
        { IsIPv4MappedToIPv6: true } => address.MapToIPv4().ToString(),
        _ => address.ToString(),
    };

    public static string? Of(HttpContext context) => Normalize(context.Connection.RemoteIpAddress);
}
