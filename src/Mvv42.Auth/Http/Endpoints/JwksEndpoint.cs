using Mvv42.Auth.Keys;

namespace Mvv42.Auth.Http.Endpoints;

public static class JwksEndpoint
{
    /// <summary>GET /auth/.well-known/jwks.json — public keys of every key in the store.</summary>
    public static void MapJwks(this IEndpointRouteBuilder app) =>
        app.MapGet("/.well-known/jwks.json", (HttpContext ctx, SigningKeyStore keys) =>
        {
            ctx.Response.Headers.CacheControl = "public, max-age=300";
            return Results.Json(keys.GetJwks());
        });
}
