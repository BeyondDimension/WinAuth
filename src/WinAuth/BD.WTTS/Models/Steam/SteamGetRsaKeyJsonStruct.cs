namespace BD.WTTS.Models;

public sealed class SteamGetRsaKeyJsonStruct
{
    [JsonPropertyName("success")]
    public bool Success { get; set; }

    [JsonPropertyName("publickey_mod")]
    public string PublicKeyMod { get; set; } = string.Empty;

    [JsonPropertyName("publickey_exp")]
    public string PublicKeyExp { get; set; } = string.Empty;

    [JsonPropertyName("timestamp")]
    public string TimeStamp { get; set; } = string.Empty;

    [JsonPropertyName("token_gid")]
    public string TokenGId { get; set; } = string.Empty;
}
