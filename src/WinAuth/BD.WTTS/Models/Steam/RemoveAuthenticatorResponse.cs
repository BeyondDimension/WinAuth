namespace BD.WTTS.Models;

public class RemoveAuthenticatorResponse
{
    [JsonPropertyName("response")]
    public RemoveAuthenticatorResponseResponse? Response { get; set; }
}

public class RemoveAuthenticatorResponseResponse
{
    [JsonPropertyName("success")]
    public bool Success { get; set; }

    [JsonPropertyName("revocation_attempts_remaining")]
    public int RevocationAttemptsRemaining { get; set; }
}