using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WinAuth
{
    sealed class SteamDoLoginJsonStruct
    {
        public bool Success { get; set; }

        public string Redirect_uri { get; set; }

        public string Emailsteamid { get; set; } = string.Empty;

        public bool Captcha_needed { get; set; }

        public string Captcha_gid { get; set; } = string.Empty;

        public bool Emailauth_needed { get; set; }

        public string Emaildomain { get; set; } = string.Empty;

        public bool Requires_twofactor { get; set; }

        public bool Login_complete { get; set; }

        public string? Oauth { get; set; }

        public string Message { get; set; } = string.Empty;
    }

    sealed class SteamDoLoginOauthJsonStruct
    {
        public string Oauth_token { get; set; } = string.Empty;

        public string Steamid { get; set; } = string.Empty;

        public string Account_name { get; set; }

        public string Wgtoken { get; set; }

        public string Wgtoken_secure { get; set; }

        public string Webcookie { get; set; }
    }

    sealed class SteamDoLoginHasPhoneJsonStruct
    {
        public bool Has_phone { get; set; }

        public bool Fatal { get; set; }

        public bool Success { get; set; }

        public int PhoneTimeMinutesOff { get; set; }
    }

    sealed class SteamDoLoginTfaJsonStruct
    {
        public SteamDoLoginSteamDataJsonStruct Response { get; set; }
    }

    sealed class SteamDoLoginSteamDataJsonStruct
    {
        public int Status { get; set; }

        public string Shared_secret { get; set; } = string.Empty;

        public string Serial_number { get; set; } = string.Empty;

        public string Revocation_code { get; set; } = string.Empty;

        //实际上不会返回该串数据，只是为了SteamData方便序列化而加上
        public string Steamid { get; set; } = string.Empty;

        //实际上不会返回该串数据，只是为了SteamData方便序列化而加上
        public string Steamguard_scheme { get; set; } = string.Empty;

        public string Server_time { get; set; } = string.Empty;

        public string Uri { get; set; } = string.Empty;

        public string Account_name { get; set; } = string.Empty;

        public string Token_gid { get; set; } = string.Empty;

        public string Identity_secret { get; set; } = string.Empty;

        public string Secret_1 { get; set; } = string.Empty;

        public string Phone_number_hint { get; set; } = string.Empty;
    }

    sealed class SteamDoLoginFinalizeJsonStruct
    {
        public SteamDoLoginFinalizeResponseJsonStruct Response { get; set; }
    }

    sealed class SteamDoLoginFinalizeResponseJsonStruct
    {
        public int Status { get; set; }

        public string Server_time { get; set; } = string.Empty;

        public bool Success { get; set; }

        public bool Want_more { get; set; }
    }
}
