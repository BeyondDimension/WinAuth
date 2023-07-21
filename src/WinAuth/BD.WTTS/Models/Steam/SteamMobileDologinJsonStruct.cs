namespace BD.WTTS.Models;

public class SteamMobileDologinJsonStruct
{
    [JsonPropertyName("success")]
    public bool Success { get; set; }

    [JsonPropertyName("requires_twofactor")]
    public bool RequiresTwofactor { get; set; }

    [JsonPropertyName("login_complete")]
    public bool LoginComplete { get; set; }

    [JsonPropertyName("transfer_urls")]
    public string[]? TransferUrls { get; set; }

    [JsonPropertyName("transfer_parameters")]
    public Transfer_Parameters? TransferParameters { get; set; }
}

public class Transfer_Parameters
{
    [JsonPropertyName("steamid")]
    public string? Steamid { get; set; }

    [JsonPropertyName("token_secure")]
    public string? TokenSecure { get; set; }

    [JsonPropertyName("auth")]
    public string? Auth { get; set; }

    [JsonPropertyName("remember_login")]
    public bool RememberLogin { get; set; }

    [JsonPropertyName("webcookie")]
    public string? WebCookie { get; set; }
}
