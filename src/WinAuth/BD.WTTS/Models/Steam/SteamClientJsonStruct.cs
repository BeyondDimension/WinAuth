using static WinAuth.SteamClient;

namespace BD.WTTS.Models;

public sealed class SteamRefreshJsonStruct
{
    [JsonPropertyName("token")]
    public string Token { get; set; } = string.Empty;

    [JsonPropertyName("token_secure")]
    public string TokenSecure { get; set; } = string.Empty;
}

public sealed class SteamGetConfirmationJsonStruct
{
    [JsonPropertyName("success")]
    public bool Success { get; set; }

    [JsonPropertyName("html")]
    public string Html { get; set; } = string.Empty;
}

public sealed class SteamSessionDataStruct
{
    [JsonPropertyName("steamid")]
    public string SteamId { get; set; } = string.Empty;

    [JsonPropertyName("cookies")]
    public string Cookies { get; set; } = string.Empty;

    [JsonPropertyName("oauthtoken")]
    public string OAuthToken { get; set; } = string.Empty;

    [JsonPropertyName("confs")]
    public ConfirmationPoller? Confirmations { get; set; }
}
