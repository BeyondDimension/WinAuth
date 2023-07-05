namespace BD.WTTS.Models;

public class GetUserCountryResponse
{
    [JsonPropertyName("response")]
    public GetUserCountryResponseResponse? Response { get; set; }
}

public class GetUserCountryResponseResponse
{
    [JsonPropertyName("country")]
    public string? Country { get; set; }
}