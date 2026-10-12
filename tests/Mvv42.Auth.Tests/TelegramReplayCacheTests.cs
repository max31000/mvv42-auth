using Microsoft.Extensions.Caching.Memory;
using Mvv42.Auth.Telegram;

namespace Mvv42.Auth.Tests;

public class TelegramReplayCacheTests
{
    private readonly TelegramReplayCache _cache = new(new MemoryCache(new MemoryCacheOptions()), TimeSpan.FromHours(1));

    [Fact]
    public void TryUse_SecondTime_IsFalse()
    {
        Assert.True(_cache.TryUse("abc"));
        Assert.False(_cache.TryUse("abc"));
        Assert.False(_cache.TryUse(" ABC "));
    }

    /// <summary>A registration refusal hands the payload back: the shell resends the same widget data with a code.</summary>
    [Fact]
    public void Release_MakesTheHashUsableAgain_Once()
    {
        Assert.True(_cache.TryUse("abc"));
        _cache.Release("abc");

        Assert.True(_cache.TryUse("abc"));
        Assert.False(_cache.TryUse("abc"));
    }

    /// <summary>A refused payload can come back at most <see cref="TelegramReplayCache.MaxReleases"/> times, then it stays used.</summary>
    [Fact]
    public void Release_IsBoundedPerHash()
    {
        Assert.True(_cache.TryUse("h"));
        for (var i = 0; i < TelegramReplayCache.MaxReleases; i++)
        {
            _cache.Release("h");
            Assert.True(_cache.TryUse("h"));
        }

        _cache.Release("h");
        Assert.False(_cache.TryUse("h"));
        Assert.Equal(5, TelegramReplayCache.MaxReleases);
    }
}
