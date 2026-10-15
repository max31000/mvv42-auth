using Prometheus;

namespace Mvv42.Auth.Http;

/// <summary>
/// Prometheus metrics of the service (mvv42-infra docs/specs/2026-10-16-app-metrics.md): aggregates only —
/// never a user id, Telegram id, IP or raw path in a label.
/// </summary>
internal static class AuthMetrics
{
    private static readonly object Gate = new();
    private static bool _defaultsConfigured;

    /// <summary>Login attempts by <c>login_events.result</c> (counted even when the journal write fails).</summary>
    public static readonly Counter Logins = Metrics.CreateCounter(
        "mvv42_auth_logins_total", "Login attempts by result (values of login_events.result).", "result");

    /// <summary>
    /// Process and runtime metrics stay; .NET EventCounters and Meters are off (many series, little use here).
    /// Must run before the first metric is collected; idempotent (test hosts start many apps per process).
    /// </summary>
    public static void ConfigureDefaults()
    {
        lock (Gate)
        {
            if (_defaultsConfigured) return;
            Metrics.SuppressDefaultMetrics(new SuppressDefaultMetricOptions { SuppressEventCounters = true, SuppressMeters = true });
            _defaultsConfigured = true;
        }
    }
}
