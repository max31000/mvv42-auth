namespace Mvv42.Auth.Options;

/// <summary>Section <c>Telegram</c>. Env vars use <c>Telegram__*</c>.</summary>
public sealed class TelegramOptions
{
    public const string Section = "Telegram";

    /// <summary>Bot token; HMAC secret for the Login Widget is SHA256(BotToken).</summary>
    public string BotToken { get; set; } = "";

    /// <summary>Bot username the widget uses (informational; the widget itself lives in the shell).</summary>
    public string BotUsername { get; set; } = "mv_cashpulse_bot";

    /// <summary>Maximum age of <c>auth_date</c>.</summary>
    public TimeSpan AuthDateWindow { get; set; } = TimeSpan.FromHours(1);

    /// <summary>Tolerated clock drift for <c>auth_date</c> in the future.</summary>
    public TimeSpan AuthDateFutureSkew { get; set; } = TimeSpan.FromSeconds(60);
}
