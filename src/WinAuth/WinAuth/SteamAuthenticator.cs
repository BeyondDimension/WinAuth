/*
 * Copyright (C) 2011 Colin Mackie.
 * This software is distributed under the terms of the GNU General Public License.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using System.Collections.Specialized;
using static WinAuth.SteamClient.Utils;
using Exception = System.Exception;

namespace WinAuth;

[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
[MPObj(keyAsPropertyName: true)]
public sealed partial class SteamAuthenticator : AuthenticatorValueDTO
{
    HttpClient _httpClient;
    
    /// <summary>
    /// Number of characters in code
    /// </summary>
    const int CODE_DIGITS = 5;

    /// <summary>
    /// Steam issuer for KeyUri
    /// </summary>
    const string STEAM_ISSUER = "Steam";

    /// <summary>
    /// Create a new Authenticator object
    /// </summary>
    [MPConstructor]
    public SteamAuthenticator() : base(CODE_DIGITS)
    {
        Issuer = STEAM_ISSUER;
        HttpClientHandler handler = new HttpClientHandler
        {
            AllowAutoRedirect = true,
            AutomaticDecompression = DecompressionMethods.Deflate | DecompressionMethods.GZip,
            MaxAutomaticRedirections = 1000,
        };
        _httpClient = new HttpClient(handler);
        _httpClient.DefaultRequestHeaders.Add("Accept", "text/javascript, text/html, application/xml, text/xml, */*");
        _httpClient.DefaultRequestHeaders.Add("Referer", COMMUNITY_BASE);
        //httpClient.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30");
        _httpClient.DefaultRequestHeaders.Add("User-Agent", UserAgent.Default);
        _httpClient.Timeout = new TimeSpan(0, 0, 30);
        _httpClient.DefaultRequestHeaders.ExpectContinue = false;
    }

    [IgnoreDataMember]
    [MPIgnore]
#if __HAVE_N_JSON__
    [N_JsonIgnore]
#endif
#if !__NOT_HAVE_S_JSON__
    [S_JsonIgnore]
#endif
    public override AuthenticatorPlatform Platform => AuthenticatorPlatform.Steam;

    /// <summary>
    /// Returned serial number of authenticator
    /// </summary>
    public string? Serial { get; set; }

    /// <summary>
    /// Random device ID we created and registered
    /// </summary>
    public string? DeviceId { get; set; }

    /// <summary>
    /// JSON steam data
    /// </summary>
    public string? SteamData { get; set; }

    /// <summary>
    /// revocation_code
    /// </summary>
    [IgnoreDataMember]
    [MPIgnore]
#if __HAVE_N_JSON__
    [N_JsonIgnore]
#endif
#if !__NOT_HAVE_S_JSON__
    [S_JsonIgnore]
#endif
    public string? RecoveryCode => string.IsNullOrEmpty(SteamData)
        ? null
        : JsonSerializer.Deserialize(SteamData, SteamJsonContext.Default.SteamConvertSteamDataJsonStruct)
            ?.RevocationCode;

    /// <summary>
    /// account_name
    /// </summary>
    [IgnoreDataMember]
    [MPIgnore]
#if __HAVE_N_JSON__
    [N_JsonIgnore]
#endif
#if !__NOT_HAVE_S_JSON__
    [S_JsonIgnore]
#endif
    public string? AccountName => string.IsNullOrEmpty(SteamData)
        ? null
        : JsonSerializer.Deserialize(SteamData, SteamJsonContext.Default.SteamConvertSteamDataJsonStruct)?.AccountName;

    /// <summary>
    /// steamid64
    /// </summary>
    [IgnoreDataMember]
    [MPIgnore]
#if __HAVE_N_JSON__
    [N_JsonIgnore]
#endif
#if !__NOT_HAVE_S_JSON__
    [S_JsonIgnore]
#endif
    public string? SteamId64 => string.IsNullOrEmpty(SteamData)
        ? null
        : JsonSerializer.Deserialize(SteamData, SteamJsonContext.Default.SteamConvertSteamDataJsonStruct)?.SteamId;

    /// <summary>
    /// JSON session data
    /// </summary>
    public string? SessionData { get; set; }

    protected override bool ExplicitHasValue()
    {
        return base.ExplicitHasValue() && Serial != null && DeviceId != null && SteamData != null &&
               SessionData != null;
    }

    /// <summary>
    /// Number of minutes to ignore syncing if network error
    /// </summary>
    const int SYNC_ERROR_MINUTES = 60;

    /// <summary>
    /// Number of attempts to activate
    /// </summary>
    const int ENROLL_ACTIVATE_RETRIES = 30;

    /// <summary>
    /// Incorrect activation code
    /// </summary>
    const int INVALID_ACTIVATION_CODE = 89;

    /// <summary>
    /// Time for http request when calling Sync in ms
    /// </summary>
    const int SYNC_TIMEOUT = 30000;

    /// <summary>
    /// URLs for all mobile services
    /// </summary>
    const string COMMUNITY_BASE = "https://steamcommunity.com";

    const string WEBAPI_BASE = "https://api.steampowered.com";
    const string SYNC_URL = "https://api.steampowered.com/ITwoFactorService/QueryTime/v0001";

    /// <summary>
    /// Character set for authenticator code
    /// </summary>
    static readonly char[] STEAMCHARS = new char[]
    {
        '2', '3', '4', '5', '6', '7', '8', '9', 'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'M', 'N', 'P', 'Q', 'R',
        'T', 'V', 'W', 'X', 'Y',
    };

    /// <summary>
    /// Enrolling state
    /// </summary>
    [MPObj(keyAsPropertyName: true)]
    public sealed class EnrollState
    {
        public string? Language { get; set; }

        public string? Username { get; set; }

        public string? Password { get; set; }

        // public string? CaptchaId { get; set; }
        //
        // public string? CaptchaUrl { get; set; }
        //
        // public string? CaptchaText { get; set; }
        //
        // public string? EmailDomain { get; set; }
        //
        // public string? EmailAuthText { get; set; }

        public string? ActivationCode { get; set; }

        [MessagePackFormatter(typeof(CookieFormatter))]
        public CookieContainer? Cookies { get; set; }

        public string? SteamId { get; set; }

        //public string? OAuthToken { get; set; }

        // public bool RequiresLogin { get; set; }
        //
        // public bool RequiresCaptcha { get; set; }
        //
        // public bool Requires2FA { get; set; }
        //
        // public bool RequiresEmailAuth { get; set; }

        public bool RequiresActivation { get; set; }

        public string? RevocationCode { get; set; }

        public string? SecretKey { get; set; }

        public bool Success { get; set; }

        public string? Error { get; set; }

        public string? AccessToken { get; set; }

        public string? RefreshToken { get; set; }

        public bool NoPhoneNumber { get; set; }
    }

    #region Authenticator data

    /// <summary>
    /// Time of last Sync error
    /// </summary>
    static DateTime _lastSyncError = DateTime.MinValue;

    /// <summary>
    /// Current Steam client instance
    /// </summary>
    [IgnoreDataMember]
    [MPIgnore]
#if __HAVE_N_JSON__
    [N_JsonIgnore]
#endif
#if !__NOT_HAVE_S_JSON__
    [S_JsonIgnore]
#endif
    public SteamClient? Client { get; private set; }

    #endregion

    /// <summary>
    /// Expanding offsets to retry when creating first code
    /// </summary>
    readonly int[] ENROLL_OFFSETS = new int[] { 0, -30, 30, -60, 60, -90, 90, -120, 120 };

    /// <summary>
    /// Get/set the combined secret data value
    /// </summary>
    [MPIgnore, N_JsonIgnore, S_JsonIgnore]
    public override string? SecretData
    {
        get
        {
            if (Client != null && Client.Session != null)
                SessionData = Client.Session.ToString();

            //if (Logger != null)
            //{
            //	Logger.Debug("Get Steam data: {0}, Session:{1}", (SteamData ?? string.Empty).Replace("\n"," ").Replace("\r",""), (SessionData ?? string.Empty).Replace("\n", " ").Replace("\r", ""));
            //}

            // this is the key |  serial | deviceid
            Serial.ThrowIsNull();
            DeviceId.ThrowIsNull();
            SteamData.ThrowIsNull();
            return base.SecretData
                   + "|" + ByteArrayToString(Encoding.UTF8.GetBytes(Serial))
                   + "|" + ByteArrayToString(Encoding.UTF8.GetBytes(DeviceId))
                   + "|" + ByteArrayToString(Encoding.UTF8.GetBytes(SteamData))
                   + "|" + (string.IsNullOrEmpty(SessionData) == false
                       ? ByteArrayToString(Encoding.UTF8.GetBytes(SessionData))
                       : string.Empty);
        }

        set
        {
            // extract key + serial + deviceid
            if (string.IsNullOrEmpty(value) == false)
            {
                var parts = value.Split('|');
                base.SecretData = value;
                Serial = parts.Length > 1 ? Encoding.UTF8.GetString(StringToByteArray(parts[1])) : null;
                DeviceId = parts.Length > 2 ? Encoding.UTF8.GetString(StringToByteArray(parts[2])) : null;
                SteamData = parts.Length > 3 ? Encoding.UTF8.GetString(StringToByteArray(parts[3])) : string.Empty;

                if (string.IsNullOrEmpty(SteamData) == false && SteamData[0] != '{')
                    // convert old recovation code into SteamData json
                    SteamData = "{\"revocation_code\":\"" + SteamData + "\"}";
                var session = parts.Length > 4 ? Encoding.UTF8.GetString(StringToByteArray(parts[4])) : null;

                //if (Logger != null)
                //{
                //	Logger.Debug("Set Steam data: {0}, Session:{1}", (SteamData ?? string.Empty).Replace("\n", " ").Replace("\r", ""), (SessionData ?? string.Empty).Replace("\n", " ").Replace("\r", ""));
                //}

                if (string.IsNullOrEmpty(session) == false)
                    SessionData = session;
            }
            else
            {
                SecretKey = null;
                Serial = null;
                DeviceId = null;
                SteamData = null;
                SessionData = null;
            }
        }
    }

    /// <summary>
    /// Get (or create) the current Steam client for this Authenticator
    /// </summary>
    /// <returns>current or new SteamClient</returns>
    public SteamClient GetClient()
    {
        lock (this)
        {
            Client ??= new SteamClient(this, SessionData);

            return Client;
        }
    }

    /// <summary>
    /// Perform a request to the Steam WebAPI service
    /// </summary>
    /// <param name="url">API url</param>
    /// <param name="method">GET or POST</param>
    /// <param name="data">Name-data pairs</param>
    /// <param name="cookies">current cookie container</param>
    /// <param name="headers"></param>
    /// <param name="timeout"></param>
    /// <returns>response body</returns>
    async Task<string> RequestAsync(string url, string method, NameValueCollection? data = null,
        CookieContainer? cookies = null, NameValueCollection? headers = null, int timeout = 0)
    {
        // create form-encoded data for query or body
        var query = data == null
            ? string.Empty
            : string.Join('&',
                Array.ConvertAll(data.AllKeys,
                    key => string.Format("{0}={1}", HttpUtility.UrlEncode(key), HttpUtility.UrlEncode(data[key]))));
        if (string.Compare(method, "GET", true) == 0)
            url += (!url.Contains('?', StringComparison.CurrentCulture) ? '?' : '&') + query;

        //ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback((sender, certificate, chain, sslPolicyErrors) =>
        //{
        //    return true;
        //});
        // call the server
        //HttpWebRequest request = GeneralHttpClientFactory(url);
        
        using var httpClient = _httpClient;
        
        if (headers != null)
        {
            for (int i = 0; i < headers.Count; i++)
            {
                httpClient.DefaultRequestHeaders.Add(headers.AllKeys[i].ThrowIsNull(), headers.Get(i));
            }
        }

        try
        {
            HttpResponseMessage responseMessage;

            string resultstring;
            if (string.Compare(method, "POST", true) == 0)
            {
                HttpContent content = new StringContent(query, Encoding.UTF8, "application/x-www-form-urlencoded");
                //content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded", "charset=UTF-8");
                content.Headers.ContentLength = query.Length;
                responseMessage = await httpClient.PostAsync(url, content);
            }
            else
            {
                responseMessage = await httpClient.GetAsync(url);
            }

            LogRequest(method, url, cookies, data,
                responseMessage.StatusCode.ToString() + " " + responseMessage.RequestMessage);

            // 请求是否成功
            if (responseMessage.StatusCode == HttpStatusCode.TooManyRequests)
            {
                throw new WinAuthSteamToManyRequestException(Strings.error_TooManyRequests);
            }

            if (responseMessage.StatusCode != HttpStatusCode.OK)
                throw new WinAuthInvalidRequestException(string.Format("{0}: {1}", (int)responseMessage.StatusCode,
                    responseMessage.RequestMessage));

            resultstring = await responseMessage.Content.ReadAsStringAsync();

            LogRequest(method, url, cookies, data, resultstring);
            return resultstring;
        }
        catch (Exception ex)
        {
            LogException(method, url, cookies, data, ex);

            if (ex is WebException exception && exception.Response != null &&
                ((HttpWebResponse)exception.Response).StatusCode == HttpStatusCode.Forbidden)
                throw new WinAuthUnauthorisedRequestException(ex);

            throw new WinAuthInvalidRequestException(ex.Message, ex);
        }
    }

    async Task CheckCookiesAsync(EnrollState state)
    {
        // get session
        if (state.Cookies == null || state.Cookies.Count == 0)
        {
            state.Cookies = new CookieContainer();
            state.Cookies.Add(new Uri(COMMUNITY_BASE + "/"), new Cookie("mobileClientVersion", "3067969+%282.1.3%29"));
            state.Cookies.Add(new Uri(COMMUNITY_BASE + "/"), new Cookie("mobileClient", "android"));
            state.Cookies.Add(new Uri(COMMUNITY_BASE + "/"), new Cookie("steamid", ""));
            state.Cookies.Add(new Uri(COMMUNITY_BASE + "/"), new Cookie("steamLogin", ""));
            state.Cookies.Add(new Uri(COMMUNITY_BASE + "/"), new Cookie("Steam_Language", state.Language));
            state.Cookies.Add(new Uri(COMMUNITY_BASE + "/"), new Cookie("dob", ""));

            var headers = new NameValueCollection
            {
                { "X-Requested-With", "com.valvesoftware.android.steam.community" },
            };

            _ = await RequestAsync(
                "https://steamcommunity.com/login?oauth_client_id=DE45CD61&oauth_scope=read_profile%20write_profile%20read_client%20write_client",
                "GET", null, state.Cookies, headers);
        }
    }

    public async Task<(SteamGetRsaKeyJsonStruct response, string encryptedPassword)> GetRsaKeyAndEncryptedPasswordAsync(
        EnrollState state)
    {
        await CheckCookiesAsync(state);
        state.Username.ThrowIsNull();
        state.Password.ThrowIsNull();
        // Steam strips any non-ascii chars from username and password
        state.Username = U0000_U007F_Regex().Replace(state.Username, string.Empty);
        state.Password = U0000_U007F_Regex().Replace(state.Password, string.Empty);

        // get the user's RSA key
        NameValueCollection data = new() { { "donotache", donotache_value }, { "username", state.Username } };
        var response = await RequestAsync(COMMUNITY_BASE + "/login/getrsakey", "POST", data, state.Cookies);

        //源生成
        var rsaresponse =
            JsonSerializer.Deserialize<SteamGetRsaKeyJsonStruct>(response,
                SteamJsonContext.Default.SteamGetRsaKeyJsonStruct);
        if (rsaresponse?.Success != true)
            throw new WinAuthInvalidEnrollResponseException(
                $"Cannot get steam information for user: {state.Username}, response: {response}");
        rsaresponse.PublicKeyExp.ThrowIsNull();
        rsaresponse.PublicKeyMod.ThrowIsNull();
        rsaresponse.TimeStamp.ThrowIsNull();
        // encrypt password with RSA key
        //RNGCryptoServiceProvider random = new();
        byte[] encryptedPassword;
        using (var rsa = new RSACryptoServiceProvider())
        {
            var passwordBytes = Encoding.ASCII.GetBytes(state.Password);
            var p = rsa.ExportParameters(false);
            p.Exponent = StringToByteArray(rsaresponse.PublicKeyExp);
            p.Modulus = StringToByteArray(rsaresponse.PublicKeyMod);
            rsa.ImportParameters(p);
            encryptedPassword = rsa.Encrypt(passwordBytes, false);
        }

        return (rsaresponse, Convert.ToBase64String(encryptedPassword));
    }

    /// <summary>
    /// 调用Steam添加令牌接口
    /// </summary>
    /// <param name="state"></param>
    /// <returns>调用成功返回true</returns>
    public async Task<bool> AddAuthenticatorAsync(EnrollState state)
    {
        if (string.IsNullOrEmpty(state.AccessToken)) throw new Exception("登陆信息已失效");
        state.Error = null;
        var data = new NameValueCollection();
        if (ServerTimeDiff == default)
            await Task.Run(Sync);
        var deviceId = BuildRandomId();
        data.Add("steamid", state.SteamId);
        data.Add("authenticator_time", ServerTime.ToString());
        data.Add("authenticator_type", "1");
        data.Add("device_identifier", deviceId);
        data.Add("sms_phone_id", "1");
        const string url_ITwoFactorService_AddAuthenticator_v0001 = "/ITwoFactorService/AddAuthenticator/v1";
        var response = await RequestAsync(
            WEBAPI_BASE + url_ITwoFactorService_AddAuthenticator_v0001 + $"/?access_token={state.AccessToken}",
            "POST", data);
        var tfaresponse =
            JsonSerializer.Deserialize<SteamDoLoginTfaJsonStruct>(response,
                SteamJsonContext.Default.SteamDoLoginTfaJsonStruct);
        tfaresponse.ThrowIsNull();
        if (tfaresponse.Response == null)
        {
            state.AccessToken = null;
            state.Cookies = null;
            state.Error = Strings.error_invalid_response_from_steam_.Format(response);
            return false;
        }

        if (!response.Contains("status", StringComparison.CurrentCulture) || tfaresponse.Response.Status == 84)
        {
            // invalid response
            state.Error = Strings.error_ITwoFactorService_AddAuthenticator_v0001;
            return false;
        }

        // if (!response.Contains("shared_secret", StringComparison.CurrentCulture))
        // {
        //     // invalid response
        //     state.Error = Strings.error_invalid_response_from_steam_.Format(response);
        //     return false;
        // }

        //账号没有绑定手机号
        switch (tfaresponse.Response.Status)
        {
            case 2:
                //state.Error = Strings.error_steamguard_phoneajax_.Format(Environment.NewLine);
                state.Error = "账号没有绑定的手机号，请根据指示添加手机号";
                state.NoPhoneNumber = true;
                return false;
            case 29:
                state.Error = Strings.error_HasAuthenticator;
                return false;
        }

        state.NoPhoneNumber = false;
        
        // save data into this authenticator
        var secret = tfaresponse.Response.SharedSecret;
        //SecretKey = Convert.FromBase64String(secret);
        SecretKey = Base64Extensions.Base64DecodeToByteArray_Nullable(secret);
        Serial = tfaresponse.Response.SerialNumber;
        DeviceId = deviceId;
        state.RevocationCode = tfaresponse.Response.RevocationCode;

        // add the steamid into the data
        var steamdata = tfaresponse.Response;
        if (steamdata.SteamId == string.Empty && state.SteamId != null)
            steamdata.SteamId = state.SteamId;
        if (steamdata.SteamGuardScheme == string.Empty)
            steamdata.SteamGuardScheme = "2";
        SteamData = JsonSerializer.Serialize(steamdata,
            SteamJsonContext.Default.SteamDoLoginSteamDataJsonStruct);

        // calculate server drift
        var servertime = long.Parse(tfaresponse.Response.ServerTime) * 1000;
        ServerTimeDiff = servertime - CurrentTime;
        LastServerTime = DateTime.Now.Ticks;

        state.RequiresActivation = true;

        state.Error = Strings.RequiresActivation;
        return true;
    }

    public async Task<bool> FinalizeAddAuthenticatorAsync(EnrollState state)
    {
        if (string.IsNullOrEmpty(state.AccessToken)) throw new Exception("登陆信息已失效");
        state.Error = null;
        var data = new NameValueCollection();
        if (ServerTimeDiff == default)
            await Task.Run(Sync);
        // finalize adding the authenticator
        data.Clear();
        data.Add("steamid", state.SteamId);
        data.Add("activation_code", state.ActivationCode);
        data.Add("validate_sms_code", "1");

        // try and authorise
        var retries = 0;
        while (state.RequiresActivation == true && retries < ENROLL_ACTIVATE_RETRIES)
        {
            data.Add("authenticator_code", CalculateCode(false));
            data.Add("authenticator_time", ServerTime.ToString());
            var response = await RequestAsync(
                WEBAPI_BASE + $"/ITwoFactorService/FinalizeAddAuthenticator/v1/?access_token={state.AccessToken}",
                "POST",
                data);
            var finalizeresponse = JsonSerializer.Deserialize<SteamDoLoginFinalizeJsonStruct>(response,
                SteamJsonContext.Default.SteamDoLoginFinalizeJsonStruct);
            finalizeresponse.ThrowIsNull();
            if (finalizeresponse.Response == null)
            {
                state.Error = Strings.error_invalid_response_from_steam_.Format(response);
                return false;
            }

            if (response.IndexOf("status") != -1 && finalizeresponse.Response.Status == INVALID_ACTIVATION_CODE)
            {
                state.Error = Strings.error_invalid_activation_code;
                return false;
            }

            // reset our time
            if (response.IndexOf("server_time") != -1)
            {
                var servertime = long.Parse(finalizeresponse.Response.ServerTime) * 1000;
                ServerTimeDiff = servertime - CurrentTime;
                LastServerTime = DateTime.Now.Ticks;
            }

            // check success
            if (finalizeresponse.Response.Success == true)
            {
                if (response.IndexOf("want_more") != -1 && finalizeresponse.Response.WantMore == true)
                {
                    ServerTimeDiff += Period * 1000L;
                    retries++;
                    continue;
                }

                state.RequiresActivation = false;
                break;
            }

            ServerTimeDiff += Period * 1000L;
            retries++;
        }

        if (state.RequiresActivation == true)
        {
            state.Error = Strings.error_on_activating;
            return false;
        }

        // mark and successful and return key
        state.Success = true;
        state.SecretKey = ByteArrayToString(SecretKey.ThrowIsNull());

        // // send confirmation email
        // data.Clear();
        // data.Add("access_token", state.AccessToken);
        // data.Add("steamid", state.SteamId);
        // data.Add("email_type", "2"); 
        //
        // _ = await RequestAsync(WEBAPI_BASE + "/ITwoFactorService/SendEmail/v0001", "POST", data);

        return true;
    }

    public async Task<string?> GetUserCountry(string accessToken, string steamId)
    {
        var data = new NameValueCollection();
        data.Add("steamid", steamId);
        var response =
            await RequestAsync(WEBAPI_BASE + $"/IUserAccountService/GetUserCountry/v1?access_token={accessToken}",
                "POST", data);
        var jsonObj = JsonSerializer.Deserialize(response, SteamPhoneNumberJsonContext.Default.GetUserCountryResponse);
        return jsonObj?.Response?.Country;
    }

    /// <summary>
    /// Steam账户添加绑定手机号
    /// </summary>
    /// <param name="accessToken"></param>
    /// <param name="steamId"></param>
    /// <param name="phoneNumber"></param>
    /// <param name="confirmationEmail"></param>
    /// <param name="countryCode"></param>
    /// <returns>返回错误信息，返回为null则执行成功</returns>
    public async Task<string?> AddPhoneNumberAsync(string accessToken, string steamId, string phoneNumber,
        bool confirmationEmail = false, string? countryCode = null)
    {
        string response;
        if (!confirmationEmail)
        {
            if (string.IsNullOrEmpty(countryCode))
                countryCode = await GetUserCountry(accessToken, steamId);
            var data = new NameValueCollection();
            data.Add("phone_number", phoneNumber);
            data.Add("phone_country_code", countryCode);
            response =
                await RequestAsync(
                    WEBAPI_BASE + $"/IPhoneService/SetAccountPhoneNumber/v1?access_token={accessToken}", "POST",
                    data);
            var steamAddPhoneNumberResponse =
                JsonSerializer.Deserialize(response, SteamPhoneNumberJsonContext.Default.SteamAddPhoneNumberResponse);
            steamAddPhoneNumberResponse.ThrowIsNull();
            steamAddPhoneNumberResponse.Response.ThrowIsNull();

            if (steamAddPhoneNumberResponse.Response.ConfirmationEmailAddress == null) return "账号没有绑定邮箱";
        }

        response = await RequestAsync(
            WEBAPI_BASE + $"/IPhoneService/IsAccountWaitingForEmailConfirmation/v1?access_token={accessToken}",
            "POST");

        var waitingForEmailConfirmationResponse =
            JsonSerializer.Deserialize(response,
                SteamPhoneNumberJsonContext.Default.IsAccountWaitingForEmailConfirmationResponse);

        waitingForEmailConfirmationResponse.ThrowIsNull();
        waitingForEmailConfirmationResponse.Response.ThrowIsNull();

        if (!waitingForEmailConfirmationResponse.Response.AwaitingEmailConfirmation)
        {
            response = await RequestAsync(
                WEBAPI_BASE + $"/IPhoneService/SendPhoneVerificationCode/v1?access_token={accessToken}",
                "POST");
            
            return null;
        }

        return "请确认邮件内的链接";
    }

    /// <summary>
    /// Steam移除安全防护
    /// </summary>
    /// <param name="accessToken">Steam账户验证Token</param>
    /// <param name="scheme">1 = 移除令牌验证器但保留邮箱验证，2 = 移除所有防护</param>
    /// <returns></returns>
    public async Task<bool> RemoveAuthenticatorAsync(string accessToken, int scheme = 1)
    {
        var data = new NameValueCollection();
        data.Add("revocation_code", RecoveryCode ?? throw new Exception("恢复代码为null"));
        data.Add("revocation_reason", "1");
        data.Add("steamguard_scheme", scheme.ToString());
        var response =
            await RequestAsync(WEBAPI_BASE + $"/ITwoFactorService/RemoveAuthenticator/v1?access_token={accessToken}", "POST",
                data);

        var jsonObj = JsonSerializer.Deserialize(response, SteamJsonContext.Default.RemoveAuthenticatorResponse);
        return jsonObj is { Response.Success: true };
    }

    /// <summary>
    /// Enroll the authenticator with the server
    /// </summary>
    [Obsolete("use AddAuthenticatorAsync")]
    public async Task EnrollAsync(EnrollState state)
    {
        // clear error
        state.Error = null;
        try
        {
            var data = new NameValueCollection();
            //await CheckCookiesAsync(state);
            string response;

            // if (string.IsNullOrEmpty(state.OAuthToken) == true)
            // {
            //     var (rsaResponse, encryptedPassword) = await GetRsaKeyAndEncryptedPasswordAsync(state);
            //
            //     // var nameValueCollection = new NameValueCollection();
            //     // nameValueCollection.Add("account_name", state.Username);
            //     // nameValueCollection.Add("persistence", "0");
            //     // nameValueCollection.Add("website_id", "Client");
            //     // nameValueCollection.Add("guard_data", null);
            //     // nameValueCollection.Add("language", null);
            //     // nameValueCollection.Add("encrypted_password", encryptedPassword);
            //     // nameValueCollection.Add("encryption_timestamp", rsaResponse.TimeStamp);
            //     //
            //     // SteamLoginDeviceDetails steamLoginDeviceDetails = new SteamLoginDeviceDetails()
            //     // {
            //     //     device_friendly_name = $"{Environment.MachineName} (WinAuth)",
            //     //     platform_type = EAuthTokenPlatformType.k_EAuthTokenPlatformType_MobileApp,
            //     //     os_type = (int)EOSType.Android9,
            //     // };
            //     // using (MemoryStream stream = new MemoryStream())
            //     // {
            //     //     ProtoBuf.Serializer.Serialize(stream, steamLoginDeviceDetails);
            //     //     var device = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length);
            //     //     nameValueCollection.Add("device_details", device);
            //     // }
            //
            //     // login request
            //     data = new NameValueCollection
            //     {
            //         { "password", encryptedPassword },
            //         { "username", state.Username },
            //         { "twofactorcode", "" },
            //         { "emailauth", state.EmailAuthText ?? string.Empty },
            //         { "loginfriendlyname", "" },
            //         { "captchagid", state.CaptchaId ?? "-1" },
            //         { "captcha_text", state.CaptchaText ?? "" },
            //         { "emailsteamid", state.EmailAuthText != null ? state.SteamId ?? string.Empty : string.Empty },
            //         { "rsatimestamp", rsaResponse.TimeStamp },
            //         { "remember_login", "false" },
            //         { "oauth_client_id", "DE45CD61" },
            //         { "oauth_scope", "read_profile write_profile read_client write_client" },
            //         { "donotache", donotache_value },
            //     };
            //     const string url_login_dologin = "/login/dologin/";
            //     response = await RequestAsync(COMMUNITY_BASE + url_login_dologin, "POST", data, state.Cookies);
            //     // response = await RequestAsync(
            //     //     "https://api.steampowered.com/IAuthenticationService/BeginAuthSessionViaCredentials/v1/", "POST",
            //     //     nameValueCollection, state.Cookies);
            //
            //     // nameValueCollection.Clear();
            //     // nameValueCollection.Add("client_id", "10078727937720195440");
            //     // nameValueCollection.Add("steamid", "76561198387775567");
            //     // nameValueCollection.Add("code", "NP6YM");
            //     // nameValueCollection.Add("code_type", "2");
            //
            //     // response = await RequestAsync(
            //     //     "https://api.steampowered.com/IAuthenticationService/UpdateAuthSessionWithSteamGuardCode/v1/",
            //     //     "POST", nameValueCollection, state.Cookies);
            //
            //     if (response.Contains("\"captcha_gid\":-1"))
            //     {
            //         state.Error = Strings.error_password;
            //         return false;
            //     }
            //     if (response.Contains("transfer"))
            //     {
            //         var jsonObj = JsonSerializer.Deserialize(response,
            //             SteamJsonContext.Default.SteamMobileDologinJsonStruct);
            //         jsonObj.ThrowIsNull();
            //         jsonObj.TransferParameters.ThrowIsNull();
            //         state.Requires2FA = jsonObj.RequiresTwofactor;
            //         if (!jsonObj.LoginComplete) throw new WinAuthInvalidEnrollResponseException("Login Failed");
            //         state.SteamId = jsonObj.TransferParameters.Steamid;
            //         state.OAuthToken = jsonObj.TransferParameters.Auth;
            //     }
            //     else
            //     {
            //         var loginResponse = JsonSerializer.Deserialize<SteamDoLoginJsonStruct>(response,
            //             SteamJsonContext.Default.SteamDoLoginJsonStruct);
            //         loginResponse.ThrowIsNull();
            //
            //         //if (loginresponse == null)
            //         //    throw GetWinAuthInvalidEnrollResponseException(response, url_login_dologin, new ArgumentNullException(nameof(loginresponse)));
            //
            //         if (loginResponse.EmailSteamId != string.Empty)
            //             state.SteamId = loginResponse.EmailSteamId;
            //
            //         // require captcha
            //         if (loginResponse.CaptchaNeeded == true)
            //         {
            //             state.RequiresCaptcha = true;
            //             state.CaptchaId = loginResponse.CaptchaGId;
            //             state.CaptchaUrl = COMMUNITY_BASE + "/public/captcha.php?gid=" + state.CaptchaId;
            //
            //             state.Error = Strings.CaptchaNeeded;
            //             return false;
            //         }
            //         else
            //         {
            //             state.RequiresCaptcha = false;
            //             state.CaptchaId = null;
            //             state.CaptchaUrl = null;
            //             state.CaptchaText = null;
            //         }
            //
            //         // require email auth
            //         if (loginResponse.EmailAuthNeeded == true)
            //         {
            //             if (!string.IsNullOrEmpty(loginResponse.EmailDomain))
            //             {
            //                 var emaildomain = loginResponse.EmailDomain;
            //                 if (string.IsNullOrEmpty(emaildomain) == false)
            //                     state.EmailDomain = emaildomain;
            //             }
            //
            //             state.RequiresEmailAuth = true;
            //
            //             state.Error = Strings.EmailAuthNeeded;
            //             return false;
            //         }
            //         else
            //         {
            //             state.EmailDomain = null;
            //             state.RequiresEmailAuth = false;
            //         }
            //
            //         // require 2fa auth
            //         if (loginResponse.RequiresTwoFactor == true)
            //             state.Requires2FA = true;
            //         else
            //             state.Requires2FA = false;
            //
            //         // if we didn't login, return the result
            //         if (loginResponse.LoginComplete == false || loginResponse.OAuth == null)
            //         {
            //             if (loginResponse.OAuth == null)
            //                 state.Error = Strings.error_NoOAuth;
            //             if (!string.IsNullOrEmpty(loginResponse.Message))
            //                 state.Error = loginResponse.Message;
            //             return false;
            //         }
            //
            //         // get the OAuth token - is stringified json
            //         //loginresponse.Oauth.Steamid.ThrowIsNull();
            //         var oauthjson = JsonSerializer.Deserialize<SteamDoLoginOauthJsonStruct>(loginResponse.OAuth,
            //             SteamJsonContext.Default.SteamDoLoginOauthJsonStruct);
            //         oauthjson.ThrowIsNull();
            //         state.OAuthToken = oauthjson.OAuthToken;
            //         if (oauthjson.SteamId != string.Empty)
            //         {
            //             state.SteamId = oauthjson.SteamId;
            //         }
            //     }
            // }

            //// login to webapi
            //data.Clear();
            //data.Add("access_token", state.OAuthToken);
            //response = await RequestAsync(WEBAPI_BASE + "/ISteamWebUserPresenceOAuth/Logon/v0001", "POST", data);
            //var sessionid = cookies.GetCookies(new Uri(COMMUNITY_BASE + "/"))?["sessionid"]?.Value;

            // 获取Sessionid
            // var readableCookies = cookies.GetCookies(new Uri("https://steamcommunity.com"));
            // var sessionid = readableCookies["sessionid"]?.Value;

            if (state.RequiresActivation == false)
            {
                // data.Clear();
                // data.Add("op", "has_phone");
                // data.Add("arg", "null");
                // data.Add("sessionid", sessionid);
                //
                // response = await RequestAsync(COMMUNITY_BASE + "/steamguard/phoneajax", "POST", data, cookies);
                // var jsonresponse = JsonSerializer.Deserialize<SteamDoLoginHasPhoneJsonStruct>(response, SteamJsonContext.Default.SteamDoLoginHasPhoneJsonStruct);
                // jsonresponse.ThrowIsNull();
                // var hasPhone = jsonresponse.HasPhone;
                // if (hasPhone == false)
                // {
                //     state.OAuthToken = null; // force new login
                //     state.RequiresLogin = true;
                //     state.Cookies = null;
                //     state.Error = Strings.error_steamguard_phoneajax_.Format(Environment.NewLine);
                //     return false;
                // }

                //response = Request(COMMUNITY_BASE + "/steamguard/phone_checksms?bForTwoFactor=1&bRevoke2fOnCancel=", "GET", null, cookies);
                // add a new authenticator
            }
        }
        catch (WinAuthUnauthorisedRequestException ex)
        {
            throw new WinAuthInvalidEnrollResponseException(
                "You are not allowed to add an authenticator. Have you enabled 'community-generated content' in Family View?",
                ex);
        }
        catch (WinAuthInvalidRequestException ex)
        {
            throw new WinAuthInvalidEnrollResponseException("Error enrolling new authenticator", ex);
        }

        //static JsonNode SelectTokenNotNull(string response, JsonNode token, string path, string? msg = null) =>
        //    SteamClient.Utils.SelectTokenNotNull(response, token, path, msg,
        //        GetWinAuthInvalidEnrollResponseException);

        //static string SelectTokenValueNotNull(string response, JsonNode token, string path, string? msg = null) =>
        //    SteamClient.Utils.SelectTokenValueNotNull(response, token, path, msg,
        //        GetWinAuthInvalidEnrollResponseException);
    }

    /// <summary>
    /// Synchronise this authenticator's time with Steam.
    /// </summary>
    public override void Sync()
    {
        // check if data is protected
        if (SecretKey == null && EncryptedData != null)
            throw new WinAuthEncryptedSecretDataException();

        // don't retry for 5 minutes
        if (_lastSyncError >= DateTime.Now.AddMinutes(0 - SYNC_ERROR_MINUTES))
            return;

        try
        {
            var response = RequestAsync(SYNC_URL, "POST", null, null, null, SYNC_TIMEOUT).GetAwaiter().GetResult();
            var options = new JsonSerializerOptions { TypeInfoResolver = SteamJsonContext.Default };
            var json = JsonSerializer.Deserialize<SteamSyncStruct>(response, options);
            json.ThrowIsNull();
            json.Response.ThrowIsNull();

            // get servertime in ms
            long servertime = long.Parse(json.Response.ServerTime) * 1000;

            // get the difference between the server time and our current time
            ServerTimeDiff = servertime - CurrentTime;
            LastServerTime = DateTime.Now.Ticks;

            // clear any sync error
            _lastSyncError = DateTime.MinValue;
        }
        catch (Exception e)
        {
            // don't retry for a while after error
            _lastSyncError = DateTime.Now;
            //throw;
            // set to zero to force reset
            //ServerTimeDiff = 0;
        }
    }

    /// <summary>
    /// Calculate the current code for the authenticator.
    /// </summary>
    /// <param name="resyncTime">flag to resync time</param>
    /// <param name="interval"></param>
    /// <returns>authenticator code</returns>
    protected override string CalculateCode(bool resyncTime = false, long interval = -1)
    {
        // sync time if required
        if (resyncTime || ServerTimeDiff == 0)
            if (interval > 0)
                ServerTimeDiff = (interval * Period * 1000L) - CurrentTime;
            else
                Task.Run(Sync);

        var hmac = new HMac(new Sha1Digest());
        hmac.Init(new KeyParameter(SecretKey));

        var codeIntervalArray = BitConverter.GetBytes(CodeInterval);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(codeIntervalArray);
        hmac.BlockUpdate(codeIntervalArray, 0, codeIntervalArray.Length);

        var mac = new byte[hmac.GetMacSize()];
        hmac.DoFinal(mac, 0);

        // the last 4 bits of the mac say where the code starts (e.g. if last 4 bit are 1100, we start at byte 12)
        var start = mac[19] & 0x0f;

        // extract those 4 bytes
        var bytes = new byte[4];
        Array.Copy(mac, start, bytes, 0, 4);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(bytes);
        var fullcode = BitConverter.ToUInt32(bytes, 0) & 0x7fffffff;

        // build the alphanumeric code
        var code = new StringBuilder();
        for (var i = 0; i < CODE_DIGITS; i++)
        {
            code.Append(STEAMCHARS[fullcode % STEAMCHARS.Length]);
            fullcode /= (uint)STEAMCHARS.Length;
        }

        return code.ToString();
    }

    /// <summary>
    /// Create a random Device ID string for Enrolling
    /// </summary>
    /// <returns>Random string</returns>
    static string BuildRandomId() => "android:" + Guid.NewGuid().ToString();

    /// <summary>
    /// Log an exception from a Request
    /// </summary>
    /// <param name="method">Get or POST</param>
    /// <param name="url">Request URL</param>
    /// <param name="cookies">cookie container</param>
    /// <param name="request">Request data</param>
    /// <param name="ex">Thrown exception</param>
    [Conditional("DEBUG")]
    static void LogException(string? method, string url, CookieContainer? cookies, NameValueCollection? request,
        Exception ex)
    {
        var data = new StringBuilder();
        if (cookies != null)
        {
            IEnumerable<Cookie> cookies_ = cookies.GetCookies(new Uri(url));
            foreach (Cookie cookie in cookies_)
            {
                if (data.Length == 0)
                    data.Append("Cookies:");
                else
                    data.Append('&');
                data.Append(cookie.Name + "=" + cookie.Value);
            }

            data.Append(' ');
        }

        if (request != null)
        {
            foreach (var key in request.AllKeys)
            {
                if (data.Length == 0)
                    data.Append("Req:");
                else
                    data.Append('&');
                data.Append(key + "=" + request[key]);
            }

            data.Append(' ');
        }

        Log.Error(nameof(WinAuth), ex, data.ToString());
    }

    /// <summary>
    /// Log a normal response
    /// </summary>
    /// <param name="method">Get or POST</param>
    /// <param name="url">Request URL</param>
    /// <param name="cookies">cookie container</param>
    /// <param name="request">Request data</param>
    /// <param name="response">response body</param>
    [Conditional("DEBUG")]
    static void LogRequest(string? method, string url, CookieContainer? cookies, NameValueCollection? request,
        string? response)
    {
        var data = new StringBuilder();
        if (cookies != null)
        {
            IEnumerable<Cookie> cookies_ = cookies.GetCookies(new Uri(url));
            foreach (Cookie cookie in cookies_)
            {
                if (data.Length == 0)
                    data.Append("Cookies:");
                else
                    data.Append('&');
                data.Append(cookie.Name + "=" + cookie.Value);
            }

            data.Append(' ');
        }

        if (request != null)
        {
            foreach (var key in request.AllKeys)
            {
                if (data.Length == 0)
                    data.Append("Req:");
                else
                    data.Append('&');
                data.Append(key + "=" + request[key]);
            }

            data.Append(' ');
        }

        if (response != null)
        {
            data.AppendLine();
            data.Append(response);
        }

        Log.Info(nameof(WinAuth), data.ToString());
    }

    [GeneratedRegex("[^\\u0000-\\u007F]")]
    internal static partial Regex U0000_U007F_Regex();
}