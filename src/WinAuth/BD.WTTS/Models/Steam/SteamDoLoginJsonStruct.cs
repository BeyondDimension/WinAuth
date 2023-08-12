namespace BD.WTTS.Models;

public sealed class SteamDoLoginJsonStruct
{
    [JsonPropertyName("success")]
    public bool Success { get; set; }

    [JsonPropertyName("redirect_uri")]
    public string RedirectUri { get; set; } = string.Empty;

    [JsonPropertyName("emailsteamid")]
    public string EmailSteamId { get; set; } = string.Empty;

    [JsonPropertyName("captcha_needed")]
    public bool CaptchaNeeded { get; set; }

    [JsonPropertyName("captcha_gid")]
    public string CaptchaGId { get; set; } = string.Empty;

    [JsonPropertyName("emailauth_needed")]
    public bool EmailAuthNeeded { get; set; }

    [JsonPropertyName("emaildomain")]
    public string EmailDomain { get; set; } = string.Empty;

    [JsonPropertyName("requires_twofactor")]
    public bool RequiresTwoFactor { get; set; }

    [JsonPropertyName("login_complete")]
    public bool LoginComplete { get; set; }

    [JsonPropertyName("oauth")]
    public string? OAuth { get; set; }

    [JsonPropertyName("message")]
    public string Message { get; set; } = string.Empty;
}

public sealed class SteamDoLoginOauthJsonStruct
{
    [JsonPropertyName("oauth_token")]
    public string OAuthToken { get; set; } = string.Empty;

    [JsonPropertyName("steamid")]
    public string SteamId { get; set; } = string.Empty;

    [JsonPropertyName("account_name")]
    public string AccountName { get; set; } = string.Empty;

    [JsonPropertyName("wgtoken")]
    public string WgToken { get; set; } = string.Empty;

    [JsonPropertyName("wgtoken_secure")]
    public string WgTokenSecure { get; set; } = string.Empty;

    [JsonPropertyName("webcookie")]
    public string WebCookie { get; set; } = string.Empty;
}

public sealed class SteamDoLoginHasPhoneJsonStruct
{
    [JsonPropertyName("has_phone")]
    public bool HasPhone { get; set; }

    [JsonPropertyName("fatal")]
    public bool Fatal { get; set; }

    [JsonPropertyName("success")]
    public bool Success { get; set; }

    [JsonPropertyName("phoneTimeMinutesOff")]
    public int PhoneTimeMinutesOff { get; set; }
}

public sealed class SteamDoLoginTfaJsonStruct
{
    [JsonPropertyName("response")]
    public SteamConvertSteamDataJsonStruct? Response { get; set; }
}

public sealed class SteamDoLoginFinalizeJsonStruct
{
    [JsonPropertyName("response")]
    public SteamDoLoginFinalizeResponseJsonStruct? Response { get; set; }
}

public sealed class SteamDoLoginFinalizeResponseJsonStruct
{
    [JsonPropertyName("status")]
    public int Status { get; set; }

    [JsonPropertyName("server_time")]
    public string ServerTime { get; set; } = string.Empty;

    [JsonPropertyName("success")]
    public bool Success { get; set; }

    [JsonPropertyName("want_more")]
    public bool WantMore { get; set; }
}

public sealed class SteamConvertSteamDataJsonStruct
{
    [JsonPropertyName("status")]
    public int Status { get; set; }

    [JsonPropertyName("shared_secret")]
    public string SharedSecret { get; set; } = string.Empty;

    [JsonPropertyName("serial_number")]
    public string SerialNumber { get; set; } = string.Empty;

    [JsonPropertyName("revocation_code")]
    public string RevocationCode { get; set; } = string.Empty;

    [JsonPropertyName("steamid")]
    public string SteamId { get; set; } = string.Empty;

    [JsonPropertyName("steamguard_scheme")]
    public string SteamGuardScheme { get; set; } = string.Empty;

    [JsonPropertyName("server_time")]
    public string ServerTime { get; set; } = string.Empty;

    [JsonPropertyName("uri")]
    public string Uri { get; set; } = string.Empty;

    [JsonPropertyName("account_name")]
    public string AccountName { get; set; } = string.Empty;

    [JsonPropertyName("token_gid")]
    public string TokenGid { get; set; } = string.Empty;

    [JsonPropertyName("identity_secret")]
    public string IdentitySecret { get; set; } = string.Empty;

    [JsonPropertyName("secret_1")]
    public string Secret_1 { get; set; } = string.Empty;

    [JsonPropertyName("phone_number_hint")]
    public string PhoneNumberHint { get; set; } = string.Empty;
}
