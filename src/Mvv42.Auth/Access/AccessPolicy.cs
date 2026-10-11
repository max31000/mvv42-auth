using Mvv42.Auth.Data;

namespace Mvv42.Auth.Access;

public static class AccessPolicy
{
    /// <summary>Admin = <c>users.is_admin</c> OR telegram id in <c>Auth:AdminTelegramIds</c>; evaluated on every token issue.</summary>
    public static bool IsAdmin(User user, IReadOnlySet<long> adminTelegramIds) =>
        user.IsAdmin || adminTelegramIds.Contains(user.TelegramId);

    /// <summary>
    /// Apps whose authenticated features the user may use (the <c>apps</c> claim):
    /// admin → all; <c>public</c> → every logged-in user; <c>invite</c> → with a grant; <c>admin</c> → admins only.
    /// <c>anonymous</c> does not matter here — it is a UI/app-level switch.
    /// </summary>
    public static IReadOnlyList<string> AllowedApps(bool isAdmin, IEnumerable<App> apps, IEnumerable<string> grants)
    {
        var granted = grants.ToHashSet(StringComparer.Ordinal);
        return apps
            .Where(app => isAdmin || app.Access switch
            {
                AppAccess.Public => true,
                AppAccess.Invite => granted.Contains(app.Id),
                _ => false,
            })
            .Select(app => app.Id)
            .ToList();
    }
}
