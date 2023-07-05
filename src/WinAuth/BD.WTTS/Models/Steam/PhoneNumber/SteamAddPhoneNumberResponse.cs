namespace BD.WTTS.Models;

public class SteamAddPhoneNumberResponse
{
    [JsonPropertyName("response")]
    public SteamAddPhoneNumberResponseResponse? Response { get; set; }
}

public class SteamAddPhoneNumberResponseResponse
{
    [JsonPropertyName("confirmation_email_address")]
    public string? ConfirmationEmailAddress { get; set; }

    [JsonPropertyName("phone_number_formatted")]
    public string? PhoneNumberFormatted { get; set; }
}