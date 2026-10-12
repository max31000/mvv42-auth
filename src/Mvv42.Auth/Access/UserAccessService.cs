using Microsoft.Extensions.Options;
using Mvv42.Auth.Data;
using Mvv42.Auth.Options;
using Mvv42.Auth.Tokens;

namespace Mvv42.Auth.Access;

/// <summary>A user with everything needed for a token and for <c>/me</c>, computed fresh from the DB.</summary>
public sealed record UserAccess(User User, bool IsAdmin, bool IsOwner, IReadOnlyList<App> Apps, IReadOnlySet<string> AllowedApps);

public sealed record MeUser(long Id, long TelegramId, string Name, string? Username, string? PhotoUrl, bool IsAdmin, bool IsOwner);

public sealed record MeApp(string Id, bool Anonymous, string Access, bool Granted);

/// <summary>Response of <c>/me</c> and <c>/telegram</c> (and <c>me</c> inside the <c>/invites/redeem</c> response).</summary>
public sealed record MeResponse(MeUser? User, IReadOnlyList<MeApp> Apps);

public sealed class UserAccessService(IAuthStore store, AccessTokenIssuer issuer, IOptions<AuthOptions> options)
{
    /// <summary>Owner = telegram id in <c>Auth:AdminTelegramIds</c>: the only one who may use the admin API.</summary>
    public bool IsOwner(long telegramId) => options.Value.AdminTelegramIdSet().Contains(telegramId);

    /// <summary>
    /// The single choke point for "may this user get a token / act": null for an unknown <b>or blocked</b> user
    /// (spec §10.8) → <c>/me</c> anonymous + cookies cleared, refresh 401, redeem/admin 401.
    /// </summary>
    public async Task<UserAccess?> GetAsync(long userId)
    {
        var user = await store.GetUserAsync(userId);
        if (user is null || IsEffectivelyBlocked(user))
            return null;

        var apps = await store.GetAppsAsync();
        var isAdmin = AccessPolicy.IsAdmin(user, options.Value.AdminTelegramIdSet());
        var allowed = AccessPolicy.AllowedApps(isAdmin, apps, await store.GetGrantsAsync(userId));
        return new UserAccess(user, isAdmin, IsOwner(user.TelegramId), apps, allowed.ToHashSet(StringComparer.Ordinal));
    }

    /// <summary>Owners are never treated as blocked, whatever the row says (they cannot be locked out by a stale flag).</summary>
    public bool IsEffectivelyBlocked(User user) => user.IsBlocked && !IsOwner(user.TelegramId);

    public IssuedAccessToken Issue(UserAccess access) => issuer.Issue(new AccessTokenSubject(
        access.User.Id, access.User.TelegramId, access.User.DisplayName, access.IsAdmin,
        access.Apps.Select(a => a.Id).Where(access.AllowedApps.Contains).ToList()));

    public static MeResponse ToMe(UserAccess access) => new(
        new MeUser(access.User.Id, access.User.TelegramId, access.User.DisplayName, access.User.Username, access.User.PhotoUrl,
            access.IsAdmin, access.IsOwner),
        access.Apps.Select(a => new MeApp(a.Id, a.Anonymous, a.Access, access.AllowedApps.Contains(a.Id))).ToList());

    public async Task<MeResponse> AnonymousAsync() =>
        new(null, (await store.GetAppsAsync()).Select(a => new MeApp(a.Id, a.Anonymous, a.Access, false)).ToList());
}
