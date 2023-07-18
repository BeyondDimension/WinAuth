using System.Web;
using WinAuth;
using static BD.WTTS.Models.AuthenticatorDTO;
using static BD.WTTS.Models.AuthenticatorValueDTO;

// ReSharper disable once CheckNamespace
namespace BD.WTTS.Models;

public static partial class AuthenticatorDTOExtensions
{
    public static AuthenticatorExportDTO ToExport(
        this IAuthenticatorDTO @this,
        bool compat = false)
    {
        @this.Value.ThrowIsNull();
        AuthenticatorExportDTO dto = new();

        //Match match;
        var issuer = @this.Value.Issuer;
        var label = @this.Name;
        //if (string.IsNullOrEmpty(issuer) && (match = Regex.Match(label, @"^([^\(]+)\s+\((.*?)\)(.*)")).Success == true)
        //{
        //    issuer = match.Groups[1].Value;
        //    label = match.Groups[2].Value + match.Groups[3].Value;
        //}
        //if (!string.IsNullOrEmpty(issuer) && (match = Regex.Match(label, @"^" + issuer + @"\s+\((.*?)\)(.*)")).Success)
        //{
        //    label = match.Groups[1].Value + match.Groups[2].Value;
        //}
        if (!string.IsNullOrEmpty(issuer))
        {
            dto.Issuer = issuer;
        }

        if (@this.Value.HMACType != DEFAULT_HMAC_TYPE)
        {
            dto.HMACType = @this.Value.HMACType;
        }

        if (@this.Value is BattleNetAuthenticator battleNetAuthenticator)
        {
            dto.Platform = AuthenticatorPlatform.BattleNet;
            dto.Serial = battleNetAuthenticator.Serial;
        }
        else if (@this.Value is SteamAuthenticator steamAuthenticator)
        {
            dto.Platform = AuthenticatorPlatform.Steam;
            if (!compat)
            {
                dto.DeviceId = steamAuthenticator.DeviceId;
                dto.SteamData = steamAuthenticator.SteamData;
            }
        }
        else if (@this.Value is HOTPAuthenticator hOTPAuthenticator)
        {
            dto.Platform = AuthenticatorPlatform.HOTP;
            dto.Counter = hOTPAuthenticator.Counter;
        }
        else if (@this.Value is GoogleAuthenticator googleAuthenticator)
        {
            dto.Platform = AuthenticatorPlatform.Google;
        }
        else if (@this.Value is MicrosoftAuthenticator microsoftAuthenticator)
        {
            dto.Platform = AuthenticatorPlatform.Microsoft;
        }

        dto.SecretKey = @this.Value.SecretKey;

        if (@this.Value.Period != DEFAULT_PERIOD)
        {
            dto.Period = @this.Value.Period;
        }

        dto.CodeDigits = @this.Value.CodeDigits;
        dto.Name = label;

        return dto;
    }

    /// <summary>
    /// Create a KeyUriFormat compatible URL
    /// See https://code.google.com/p/google-authenticator/wiki/KeyUriFormat
    /// </summary>
    /// <param name="this"></param>
    /// <param name="compat"></param>
    /// <returns></returns>
    public static string ToUrl(this AuthenticatorExportDTO @this, bool compat = false)
    {
        string type = "totp";
        string extraparams = string.Empty;

        //Match match;
        var issuer = @this.Issuer;
        var label = @this.Name;
        //if (string.IsNullOrEmpty(issuer) && (match = Regex.Match(label, @"^([^\(]+)\s+\((.*?)\)(.*)")).Success == true)
        //{
        //    issuer = match.Groups[1].Value;
        //    label = match.Groups[2].Value + match.Groups[3].Value;
        //}
        //if (!string.IsNullOrEmpty(issuer) && (match = Regex.Match(label, @"^" + issuer + @"\s+\((.*?)\)(.*)")).Success)
        //{
        //    label = match.Groups[1].Value + match.Groups[2].Value;
        //}
        if (!string.IsNullOrEmpty(issuer))
        {
            extraparams += "&issuer=" + HttpUtility.UrlEncode(issuer);
        }

        if (@this.HMACType != DEFAULT_HMAC_TYPE)
        {
            extraparams += "&algorithm=" + @this.HMACType.ToString();
        }

        if (@this.Platform == AuthenticatorPlatform.BattleNet)
        {
            extraparams += "&serial=" + HttpUtility.UrlEncode(@this.Serial?.Replace("-", ""));
        }
        else if (@this.Platform == AuthenticatorPlatform.Steam)
        {
            if (!compat)
            {
                extraparams += "&deviceid=" + HttpUtility.UrlEncode(@this.DeviceId);
                extraparams += "&data=" + HttpUtility.UrlEncode(@this.SteamData);
            }
        }
        else if (@this.Platform == AuthenticatorPlatform.HOTP)
        {
            type = "hotp";
            extraparams += "&counter=" + @this.Counter;
        }

        var secret = HttpUtility.UrlEncode(Base32.GetInstance().Encode(@this.SecretKey ?? Array.Empty<byte>()));

        if (@this.Period != DEFAULT_PERIOD)
        {
            extraparams += "&period=" + @this.Period;
        }

        var url = string.Format("otpauth://" + type + "/{0}?secret={1}&digits={2}{3}",
          !string.IsNullOrEmpty(issuer) ? HttpUtility.UrlPathEncode(issuer) + ":" + HttpUtility.UrlPathEncode(label) : HttpUtility.UrlPathEncode(label),
          secret,
          @this.CodeDigits,
          extraparams);

        return url;
    }
}
