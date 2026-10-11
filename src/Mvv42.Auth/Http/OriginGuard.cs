using Microsoft.Extensions.Options;
using Mvv42.Auth.Options;

namespace Mvv42.Auth.Http;

/// <summary>
/// CSRF defence in depth on top of SameSite=Strict: POST/PUT/PATCH/DELETE must carry an <c>Origin</c>
/// (or, when absent, a <c>Referer</c>) whose origin is in <c>Auth:AllowedOrigins</c>; otherwise 403.
/// </summary>
public sealed class OriginGuard(IOptions<AuthOptions> options) : IEndpointFilter
{
    public ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var request = context.HttpContext.Request;
        if (HttpMethods.IsGet(request.Method) || HttpMethods.IsHead(request.Method) || HttpMethods.IsOptions(request.Method))
            return next(context);

        return IsAllowed(request, options.Value.AllowedOriginSet())
            ? next(context)
            : ValueTask.FromResult<object?>(Results.Json(new { error = "origin_not_allowed" }, statusCode: StatusCodes.Status403Forbidden));
    }

    public static bool IsAllowed(HttpRequest request, IReadOnlySet<string> allowed)
    {
        var origin = request.Headers.Origin.ToString();
        if (string.IsNullOrEmpty(origin))
        {
            var referer = request.Headers.Referer.ToString();
            if (!Uri.TryCreate(referer, UriKind.Absolute, out var uri))
                return false;
            origin = uri.GetLeftPart(UriPartial.Authority);
        }
        return allowed.Contains(origin.TrimEnd('/'));
    }
}
