using Mvv42.Auth.Data;

namespace Mvv42.Auth.Sessions;

/// <summary>Hourly removal of expired sessions and of sessions revoked more than a day ago (spec §9.2).</summary>
public sealed class SessionCleanupService(IAuthStore store, TimeProvider time, ILogger<SessionCleanupService> logger)
    : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromHours(1);

    /// <summary>Revoked rows are kept a day for troubleshooting (e.g. a reuse incident).</summary>
    private static readonly TimeSpan RevokedRetention = TimeSpan.FromDays(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval, time);
        do
        {
            try
            {
                await CleanupOnceAsync();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "Session cleanup failed");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    public async Task CleanupOnceAsync()
    {
        var now = time.GetUtcNow().UtcDateTime;
        var deleted = await store.DeleteStaleSessionsAsync(now, now - RevokedRetention);
        if (deleted > 0)
            logger.LogInformation("Deleted {Count} stale sessions", deleted);
    }
}
