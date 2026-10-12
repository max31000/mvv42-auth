using Mvv42.Auth.Data;

namespace Mvv42.Auth.Invites;

public static class InviteLookup
{
    /// <summary>The first invite whose hash is among <paramref name="codeHashes"/>, in their order (see <see cref="InviteCodeHasher.Candidates"/>).</summary>
    public static async Task<Invite?> FindInviteAsync(this IAuthStore store, IEnumerable<string> codeHashes)
    {
        foreach (var codeHash in codeHashes)
            if (await store.GetInviteByCodeHashAsync(codeHash) is { } invite)
                return invite;
        return null;
    }
}
