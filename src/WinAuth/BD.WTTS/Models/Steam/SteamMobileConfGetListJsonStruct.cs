namespace BD.WTTS.Models;

public class SteamMobileConfGetListJsonStruct
{
    [JsonPropertyName("success")]
    public bool Success { get; set; }

    [JsonPropertyName("conf")]
    public SteamMobileTradeConf[]? Conf { get; set; }
}

public class SteamMobileTradeConf
{
    [JsonPropertyName("type")]
    public int Type { get; set; }

    [JsonPropertyName("type_name")]
    public string TypeName { get; set; } = string.Empty;

    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("creator_id")]
    public string CreatorId { get; set; } = string.Empty;

    [JsonPropertyName("nonce")]
    public string Nonce { get; set; } = string.Empty;

    [JsonPropertyName("creation_time")]
    public long CreationTime { get; set; }

    [JsonPropertyName("cancel")]
    public string Cancel { get; set; } = string.Empty;

    [JsonPropertyName("accept")]
    public string Accept { get; set; } = string.Empty;

    [JsonPropertyName("icon")]
    public string Icon { get; set; } = string.Empty;

    [JsonPropertyName("multi")]
    public bool Multi { get; set; }

    [JsonPropertyName("headline")]
    public string Headline { get; set; } = string.Empty;

    [JsonPropertyName("summary")]
    public string[]? Summary { get; set; }

    [JsonPropertyName("warn")]
    public string[]? Warn { get; set; }
}