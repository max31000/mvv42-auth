using Microsoft.Extensions.Caching.Memory;

namespace Mvv42.Auth.Telegram;

/// <summary>
/// Remembers the hashes of successfully used Login Widget payloads for as long as they would pass the
/// <c>auth_date</c> check, so an intercepted payload cannot be replayed into a second session.
/// Single instance service → an in-process cache is enough.
/// </summary>
public sealed class TelegramReplayCache(IMemoryCache cache, TimeSpan ttl)
{
    private readonly object _lock = new();

    private static string Key(string hash) => "tg-login:" + hash.Trim().ToLowerInvariant();

    /// <summary>true the first time a hash is seen within the TTL, false for a repeat.</summary>
    public bool TryUse(string hash)
    {
        var key = Key(hash);
        lock (_lock)
        {
            if (cache.TryGetValue(key, out _))
                return false;
            cache.Set(key, true, ttl);
            return true;
        }
    }

    /// <summary>
    /// Hands a hash taken by <see cref="TryUse"/> back. Only for a refused registration (<c>invite_required</c>,
    /// a bad invite code): nothing was issued, and the shell resends the same widget data with a code.
    /// </summary>
    public void Release(string hash)
    {
        lock (_lock)
            cache.Remove(Key(hash));
    }
}
