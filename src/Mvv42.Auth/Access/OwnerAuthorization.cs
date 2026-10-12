using System.Globalization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Mvv42.Auth.Options;

namespace Mvv42.Auth.Access;

/// <summary>The caller's <c>tg</c> claim is in <c>Auth:AdminTelegramIds</c> (the platform owner).</summary>
public sealed class OwnerRequirement : IAuthorizationRequirement;

/// <summary>
/// Claim-based: no DB lookup. Blocked users never get a token (spec §10.8) and the owner cannot be blocked; the admin
/// group additionally re-checks the caller through <see cref="UserAccessService.GetAsync"/>.
/// </summary>
public sealed class OwnerAuthorizationHandler(IOptions<AuthOptions> options) : AuthorizationHandler<OwnerRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, OwnerRequirement requirement)
    {
        if (long.TryParse(context.User.FindFirst("tg")?.Value, NumberStyles.None, CultureInfo.InvariantCulture, out var tg)
            && options.Value.AdminTelegramIdSet().Contains(tg))
            context.Succeed(requirement);
        return Task.CompletedTask;
    }
}
