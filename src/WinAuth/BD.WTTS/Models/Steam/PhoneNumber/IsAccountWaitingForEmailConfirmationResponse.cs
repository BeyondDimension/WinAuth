namespace BD.WTTS.Models;

public class IsAccountWaitingForEmailConfirmationResponse
{
    [JsonPropertyName("response")]
    public IsAccountWaitingForEmailConfirmationResponseResponse? Response { get; set; }
}

public class IsAccountWaitingForEmailConfirmationResponseResponse
{
    [JsonPropertyName("awaiting_email_confirmation")]
    public bool AwaitingEmailConfirmation { get; set; }

    [JsonPropertyName("seconds_to_wait")]
    public int SecondsToWait { get; set; }
}