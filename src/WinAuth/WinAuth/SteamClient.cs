/*
 * Copyright (C) 2015 Colin Mackie.
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
using BD.Common.Columns;
using Newtonsoft.Json;
using ProtoBuf;
using ReactiveUI;
using SteamKit2.Internal;
using System.Collections.Specialized;
using JsonSerializer = System.Text.Json.JsonSerializer;
using static BD.WTTS.Models.AuthenticatorValueDTO;
using static WinAuth.SteamAuthenticator;
using static WinAuth.SteamClient.Utils;

namespace WinAuth;

/// <summary>
/// SteamClient for logging and getting/accepting/rejecting trade confirmations
/// </summary>
public partial class SteamClient : IDisposable
{
    /// <summary>
    /// URLs for all mobile services
    /// </summary>
    const string COMMUNITY_DOMAIN = "steamcommunity.com";
    const string COMMUNITY_BASE = "https://" + COMMUNITY_DOMAIN;
    const string WEBAPI_BASE = "https://api.steampowered.com";
    const string API_GETWGTOKEN = WEBAPI_BASE + "/IMobileAuthService/GetWGToken/v0001";
    const string API_LOGOFF = WEBAPI_BASE + "/ISteamWebUserPresenceOAuth/Logoff/v0001";
    //const string API_LOGON = WEBAPI_BASE + "/ISteamWebUserPresenceOAuth/Logon/v0001";
    const string SYNC_URL = "https://api.steampowered.com/ITwoFactorService/QueryTime/v0001";

    /// <summary>
    /// Time for http request when calling Sync in ms
    /// </summary>
    const int SYNC_TIMEOUT = 30000;

    /// <summary>
    /// Default mobile user agent
    /// </summary>
    const string USERAGENT = "Mozilla/5.0 (Linux; Android 8.1.0; Nexus 5X Build/OPM7.181205.001) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Mobile Safari/537.36";

    /// <summary>
    /// Number of Confirmation retries
    /// </summary>
    const int DEFAULT_CONFIRMATIONPOLLER_RETRIES = 3;

    /// <summary>
    /// Delay between trade confirmation events
    /// </summary>
    public const int CONFIRMATION_EVENT_DELAY = 1000;

    /// <summary>
    /// Action for Confirmation polling
    /// </summary>
    public enum PollerAction
    {
        None = 0,
        Notify = 1,
        AutoConfirm = 2,
        SilentAutoConfirm = 3,
    }

    internal static class Utils
    {
        #region 弃用方法
        //public static string SelectTokenValueNotNull(string response, JsonNode token, string path, string? msg = null, Func<string, string, Exception?, Exception>? getWinAuthException = null)
        //{
        //    var valueToken = token;
        //    //临时修复NJ转SJ的访问子节点格式问题
        //    var nodes = path.Split('.');
        //    for (int i = 0; i < nodes.Length; i++)
        //    {
        //        valueToken = valueToken[nodes[i]];
        //    }

        //    if (valueToken != null)
        //    {
        //        var value = valueToken.GetValue<string>();
        //        if (value != null)
        //        {
        //            return value;
        //        }
        //    }
        //    getWinAuthException ??= GetWinAuthException;
        //    throw getWinAuthException(response, msg ?? "SelectTokenValueNotNull", new ArgumentNullException(path));
        //}

        //public static JsonNode SelectTokenNotNull(string response, JsonNode token, string path, string? msg = null, Func<string, string, Exception?, Exception>? getWinAuthException = null)
        //{
        //    var valueToken = token[path];
        //    if (valueToken != null)
        //    {
        //        return valueToken;
        //    }
        //    getWinAuthException ??= GetWinAuthException;
        //    throw getWinAuthException(response, msg ?? "SelectTokenNotNull", new ArgumentNullException(path));
        //}

        #endregion

        public static WinAuthException GetWinAuthException(string response, string msg, Exception? innerException = null)
        {
            return new WinAuthException(
                $"{msg}, response: {response}", innerException);
        }

        public static WinAuthException GetWinAuthInvalidEnrollResponseException(string response, string msg, Exception? innerException = null)
        {
            return new WinAuthInvalidEnrollResponseException(
                $"{msg}, response: {response}", innerException);
        }

        public const string donotache_value = "-62135596800000"; // default(DateTime).ToUniversalTime().Subtract(new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds.ToString();
    }

    /// <summary>
    /// Hold the Confirmation polling data
    /// </summary>
    public sealed class ConfirmationPoller
    {
        /// <summary>
        /// Seconds between polls
        /// </summary>
        public int Duration { get; set; }

        /// <summary>
        /// Action for new Confirmation
        /// </summary>
        public PollerAction Action { get; set; }

        /// <summary>
        /// List of current Confirmations ids
        /// </summary>
        public List<string>? Ids { get; set; }

        /// <summary>
        /// Create new ConfirmationPoller object
        /// </summary>
        public ConfirmationPoller()
        {
        }

        /// <summary>
        /// Create a JSON string of the object
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            if (Duration == 0)
            {
                return "null";
            }
            else
            {
                List<string> props = new List<string>
                {
                    "\"duration\":" + Duration,
                    "\"action\":" + (int)Action,
                };
                if (Ids != null)
                {
                    props.Add("\"ids\":[" + (Ids.Count != 0 ? "\"" + string.Join("\",\"", Ids.ToArray()) + "\"" : string.Empty) + "]");
                }

                return "{" + string.Join(",", props.ToArray()) + "}";
            }
        }

        #region 弃用方法

        ///// <summary>
        ///// Create a new ConfirmationPoller from a JSON string
        ///// </summary>
        ///// <param name="json">JSON string</param>
        ///// <returns>new ConfirmationPoller or null</returns>
        //public static ConfirmationPoller? FromJSON(string json)
        //{
        //    if (string.IsNullOrEmpty(json) == true || json == "null")
        //    {
        //        return null;
        //    }
        //    var poller = FromJSON(JsonSerializer.Deserialize(json, SteamJsonContext.Default.ConfirmationPoller));
        //    return poller?.Duration != 0 ? poller : null;
        //}

        ///// <summary>
        ///// Create a new ConfirmationPoller from a JToken
        ///// </summary>
        ///// <param name="tokens">existing JKToken</param>
        ///// <returns></returns>
        //public static ConfirmationPoller? FromJSON(ConfirmationPoller? tokens)
        //{
        //    if (tokens == null)
        //    {
        //        return null;
        //    }

        //    var poller = new ConfirmationPoller();

        //    poller.Duration = tokens.Duration;
        //    poller.Action = tokens.Action;
        //    poller.Ids = tokens.Ids;

        //    return poller.Duration != 0 ? poller : null;
        //}
        #endregion
    }

    /// <summary>
    /// A class for a single confirmation
    /// </summary>
    public sealed class Confirmation : ReactiveObject
    {
        public string Id { get; set; } = string.Empty;

        public string Key { get; set; } = string.Empty;

        public bool Offline { get; set; }

        public bool IsNew { get; set; }

        public string Image { get; set; } = string.Empty;

        private bool _ButtonEnable = true;

        public bool ButtonEnable
        {
            get => _ButtonEnable;
            set => this.RaiseAndSetIfChanged(ref _ButtonEnable, value);
        }

        private int _IsOperate;

        public int IsOperate
        {
            get => _IsOperate;
            set => this.RaiseAndSetIfChanged(ref _IsOperate, value);
        }

        private bool _NotChecked;

        /// <summary>
        /// 未勾选
        /// </summary>
        public bool NotChecked
        {
            get => _NotChecked;
            set => this.RaiseAndSetIfChanged(ref _NotChecked, value);
        }

        public string Details { get; set; } = string.Empty;

        public string Traded { get; set; } = string.Empty;

        public string When { get; set; } = string.Empty;
    }

    /// <summary>
    /// Session state to remember logins
    /// </summary>
    public sealed partial class SteamSession
    {
        public SteamSession()
        {
        }

        public SteamSession(string json)
        {
            if (string.IsNullOrEmpty(json))
                throw new ArgumentNullException(nameof(json));

            try
            {
                var session = System.Text.Json.JsonSerializer.Deserialize<SteamSession>(json);
                if (session == null)
                    throw new ArgumentNullException(nameof(session));

                this.SteamID = session.SteamID;
                this.AccessToken = session.AccessToken;
                this.RefreshToken = session.RefreshToken;
                this.SessionID = session.SessionID;
            }
            catch
            { }
        }

        [JsonPropertyName("steamid")]
        public ulong SteamID { get; set; }

        [JsonPropertyName("access_token")]
        public string? AccessToken { get; set; }

        [JsonPropertyName("refresh_token")]
        public string? RefreshToken { get; set; }

        [JsonPropertyName("sessionid")]
        public string? SessionID { get; set; }

        public async Task RefreshAccessToken(SteamClient client)
        {
            if (string.IsNullOrEmpty(this.RefreshToken))
                throw new Exception("Refresh token is empty");

            if (IsTokenExpired(this.RefreshToken))
                throw new Exception("Refresh token is expired");

            string responseStr;
            try
            {
                var postData = new NameValueCollection
                {
                    { "refresh_token", this.RefreshToken },
                    { "steamid", this.SteamID.ToString() }
                };
                responseStr = await client.RequestAsync<string>("https://api.steampowered.com/IAuthenticationService/GenerateAccessTokenForApp/v1/", "POST", postData);
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to refresh token: " + ex.Message);
            }

            var response = JsonConvert.DeserializeObject<GenerateAccessTokenForAppResponse>(responseStr);
            this.AccessToken = response.Response.AccessToken;
        }

        public bool IsAccessTokenExpired()
        {
            if (string.IsNullOrEmpty(this.AccessToken))
                return true;

            return IsTokenExpired(this.AccessToken);
        }

        public bool IsRefreshTokenExpired()
        {
            if (string.IsNullOrEmpty(this.RefreshToken))
                return true;

            return IsTokenExpired(this.RefreshToken);
        }

        private bool IsTokenExpired(string token)
        {
            var tokenComponents = token.Split('.');
            // Fix up base64url to normal base64
            var base64 = tokenComponents[1].Replace('-', '+').Replace('_', '/');

            if (base64.Length % 4 != 0)
            {
                base64 += new string('=', 4 - base64.Length % 4);
            }

            var payloadBytes = Convert.FromBase64String(base64);
            var jwt = JsonConvert.DeserializeObject<SteamAccessToken>(System.Text.Encoding.UTF8.GetString(payloadBytes));

            // Compare expire time of the token to the current time
            return DateTimeOffset.UtcNow.ToUnixTimeSeconds() > jwt.Exp;
        }

        public CookieContainer GetCookies()
        {
            if (this.SessionID == null)
                this.SessionID = GenerateSessionID();

            var cookies = new CookieContainer();
            cookies.Add(new Cookie("steamLoginSecure", this.GetSteamLoginSecure(), "/", "steamcommunity.com"));
            cookies.Add(new Cookie("sessionid", this.SessionID, "/", "steamcommunity.com"));
            cookies.Add(new Cookie("mobileClient", "android", "/", "steamcommunity.com"));
            cookies.Add(new Cookie("mobileClientVersion", "777777 3.6.1", "/", "steamcommunity.com"));
            return cookies;
        }

        private string GetSteamLoginSecure()
        {
            return this.SteamID.ToString() + "%7C%7C" + this.AccessToken;
        }

        private static string GenerateSessionID()
        {
            return GetRandomHexNumber(32);
        }

        private static string GetRandomHexNumber(int digits)
        {
            Random random = new Random();
            byte[] buffer = new byte[digits / 2];
            random.NextBytes(buffer);
            string result = String.Concat(buffer.Select(x => x.ToString("X2")).ToArray());
            if (digits % 2 == 0)
                return result;
            return result + random.Next(16).ToString("X");
        }

        public override string ToString()
        {
            return JsonSerializer.Serialize(this);
        }

        private class SteamAccessToken
        {
            [JsonProperty("exp")]
            public long Exp { get; set; }
        }

        private class GenerateAccessTokenForAppResponse
        {
            [JsonProperty("response")]
            public GenerateAccessTokenForAppResponseResponse? Response;
        }

        private class GenerateAccessTokenForAppResponseResponse
        {
            [JsonProperty("access_token")]
            public string? AccessToken { get; set; }
        }

    }

    /// <summary>
    /// Login state fields
    /// </summary>
    public bool InvalidLogin;
    public bool RequiresCaptcha;
    public string? CaptchaId;
    public string? CaptchaUrl;
    public bool Requires2FA;
    public bool RequiresEmailAuth;
    public string? EmailDomain;
    public string? Error;

    /// <summary>
    /// Current session
    /// </summary>
    public SteamSession? Session;

    /// <summary>
    /// Current authenticator
    /// </summary>
    public SteamAuthenticator Authenticator;

    // /// <summary>
    // /// Saved Html from GetConfirmations used as template for GetDetails
    // /// </summary>
    // string? ConfirmationsHtml;

    public string? SteamUserImageUrl;

    /// <summary>
    /// Query string from GetConfirmations used in GetDetails
    /// </summary>
    string? ConfirmationsQuery;

    /// <summary>
    /// Cancellation token for poller
    /// </summary>
    CancellationTokenSource? _pollerCancellation;

    /// <summary>
    /// Number of Confirmation retries
    /// </summary>
    public int ConfirmationPollerRetries = DEFAULT_CONFIRMATIONPOLLER_RETRIES;

    HttpClient? _httpClient;

    /// <summary>
    /// Delegate for Confirmation event
    /// </summary>
    /// <param name="sender"></param>
    /// <param name="newconfirmation">new Confirmation</param>
    /// <param name="action">action to be taken</param>
    public delegate void ConfirmationDelegate(object sender, SteamMobileTradeConf newconfirmation, PollerAction action);

    /// <summary>
    /// Delegate for Confirmation error
    /// </summary>
    /// <param name="sender"></param>
    /// <param name="message">error message</param>
    /// <param name="action"></param>
    /// <param name="ex">optional exception</param>
    public delegate void ConfirmationErrorDelegate(object sender, string message, PollerAction action, Exception ex);

    /// <summary>
    /// Event fired for new Confirmation
    /// </summary>
    public event ConfirmationDelegate? ConfirmationEvent;

    /// <summary>
    /// Event fired for error on polling
    /// </summary>
    public event ConfirmationErrorDelegate? ConfirmationErrorEvent;

    /// <summary>
    /// Create a new SteamClient
    /// </summary>
    public SteamClient(SteamAuthenticator auth)
    {
        Authenticator = auth;
    }

    /// <summary>
    /// Finalizer
    /// </summary>
    ~SteamClient()
    {
        _httpClient?.Dispose();
        Dispose(false);
    }

    /// <summary>
    /// Dispose the object
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Dispose this object
    /// </summary>
    /// <param name="disposing"></param>
    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            // clear resources
        }

        if (_pollerCancellation != null)
        {
            _pollerCancellation.Cancel();
            _pollerCancellation = null;
        }
    }

    #region Public

    /// <summary>
    /// Clear the client state
    /// </summary>
    public void Clear()
    {
        InvalidLogin = false;
        RequiresCaptcha = false;
        CaptchaId = null;
        CaptchaUrl = null;
        RequiresEmailAuth = false;
        EmailDomain = null;
        Requires2FA = false;
        Error = null;

        Session = null;
    }

    /// <summary>
    /// Session Set
    /// </summary>
    /// <param name="session"></param>
    public void SessionSet(string? session = null)
    {
        HttpHandlerType handler = new HttpHandlerType()
        {
            AllowAutoRedirect = true,
            AutomaticDecompression = DecompressionMethods.Deflate | DecompressionMethods.GZip,
            MaxAutomaticRedirections = 1000,
        };

        if (!string.IsNullOrEmpty(session))
        {
            Session = new SteamSession(session);

            handler.UseCookies = true;
            handler.CookieContainer = Session.GetCookies();
        }
        else
            Session = new SteamSession();

        _httpClient = new HttpClient(handler);
        //_httpClient.DefaultRequestHeaders.Add("Accept", "text/javascript, text/html, application/xml, text/xml, */*");
        //_httpClient.DefaultRequestHeaders.Add("Referer", COMMUNITY_BASE);
        //_httpClient.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30");
        _httpClient.DefaultRequestHeaders.Add("User-Agent", USERAGENT);
        _httpClient.Timeout = new TimeSpan(0, 0, 45);
        _httpClient.DefaultRequestHeaders.ExpectContinue = false;
    }

    /// <summary>
    /// Check if user is logged in
    /// </summary>
    /// <returns></returns>
    public bool IsLoggedIn() => string.IsNullOrEmpty(Session?.AccessToken) == false;

    /// <summary>
    /// Logout of the current session
    /// </summary>
    //[Obsolete("use LogoutAsync")]
    public void Logout()
    {
        if (string.IsNullOrEmpty(Session?.AccessToken) == false)
        {
            PollConfirmationsStop();

            // if (string.IsNullOrEmpty(Session.UmqId) == false)
            // {
            //     var data = new NameValueCollection
            //     {
            //         { "access_token", Session.OAuthToken },
            //         { "umqid", Session.UmqId },
            //     };
            //     GetString(API_LOGOFF, "POST", data);
            // }
        }

        Clear();
    }

    /// <summary>
    /// Get the current trade Confirmations
    /// </summary>
    /// <returns>list of Confirmation objects</returns>
    //[Obsolete("use GetConfirmationsAsync")]
    public async Task<IEnumerable<SteamMobileTradeConf>>? GetConfirmations()
    {
        long servertime = (CurrentTime + Authenticator.ServerTimeDiff) / 1000L;

        Authenticator.SteamData.ThrowIsNull();
        var ids = System.Text.Json.JsonSerializer.Deserialize(Authenticator.SteamData, SteamJsonContext.Default.SteamConvertSteamDataJsonStruct)?.IdentitySecret;
        ids.ThrowIsNull();

        // conf -> list
        var timehash = CreateTimeHash(servertime, "list", ids);

        var data = new NameValueCollection()
        {
            { "p", Authenticator.DeviceId },
            { "a", Session.SteamID.ToString() },
            { "k", timehash },
            { "t", servertime.ToString() },
            { "m", "react" },
            { "tag", "list" },
        };

        // https://steamcommunity.com/mobileconf/getlist?a=SteamID&tag=list&m=react&t=servertime&p=EncodeURL(deviceID)&k=EncodeURL(timehash)
        // 格式变为json格式返回
        string html = await RequestAsync<string>(COMMUNITY_BASE + "/mobileconf/getlist", "GET", data);

        // save last html for confirmations details
        //ConfirmationsHtml = html;
        ConfirmationsQuery = string.Join("&", Array.ConvertAll(data.AllKeys, key => string.Format("{0}={1}", HttpUtility.UrlEncode(key), HttpUtility.UrlEncode(data[key]))));

        var jsonObject = JsonSerializer.Deserialize(html, SteamJsonContext.Default.SteamMobileConfGetListJsonStruct);

        if (jsonObject?.Conf == null) return null;

        //if (Session.Confirmations != null)
        //{
        //    lock (Session.Confirmations)
        //    {
        //        Session.Confirmations.Ids ??= new List<string>();
        //        foreach (var conf in jsonObject.Conf)
        //        {
        //            // conf.IsNew = Session.Confirmations.Ids.Contains(conf.Id) == false;
        //            // if (conf.IsNew == true)
        //            // {
        //            //     Session.Confirmations.Ids.Add(conf.Id);
        //            // }
        //            if (!Session.Confirmations.Ids.Contains(conf.Id)) Session.Confirmations.Ids.Add(conf.Id);
        //        }
        //        var newIds = jsonObject.Conf.Select(t => t.Id).ToList();
        //        foreach (var confId in Session.Confirmations.Ids)
        //        {
        //            if (newIds.Contains(confId) == false)
        //            {
        //                Session.Confirmations.Ids.Remove(confId);
        //            }
        //        }
        //    }
        //}

        return jsonObject.Conf;
    }

    public async Task<(string[] receiveItems, string[] sendItems)> GetConfirmationItemImageUrls(string tradeId)
    {
        string url = COMMUNITY_BASE + "/mobileconf/details/" + tradeId + "?" + ConfirmationsQuery;

        string response = await RequestAsync<string>(url, "GET");
        if (!response.Contains("success", StringComparison.OrdinalIgnoreCase))
        {
            throw new WinAuthInvalidSteamRequestException("Invalid request from steam: " + response);
        }

        var jsonobj = JsonSerializer.Deserialize(response, SteamJsonContext.Default.SteamGetConfirmationJsonStruct);
        jsonobj.ThrowIsNull();

        List<string> sendItems = new();
        List<string> receiveItems = new();

        if (jsonobj.Success == true)
        {
            SteamUserImageUrl = GetSelfIconUrlFromConfirmationDetails(jsonobj.Html);

            var masterRegex = ConfirmationItemImageUrlsRegex().Matches(jsonobj.Html);
            foreach (Match items in masterRegex)
            {
                if (items.Success != true) throw new Exception(Strings.Error_GetQuoteTradingImage);
                var itemUrls = ConfirmationItemImageUrlsGetRegex().Matches(items.Groups[1].Value);
                if (items.Groups[0].Value.Contains("您的报价"))
                {
                    foreach (Match itemUrl in itemUrls)
                    {
                        sendItems.Add(itemUrl.Groups[1].Value);
                    }
                }
                else
                {
                    foreach (Match itemUrl in itemUrls)
                    {
                        receiveItems.Add(itemUrl.Groups[1].Value);
                    }
                }
            }
        }

        return (receiveItems.ToArray(), sendItems.ToArray());
    }

    /// <summary>
    /// Confirm or reject a specific trade confirmation
    /// </summary>
    /// <param name="trades">Id and Key</param>
    /// <param name="accept">true to accept, false to reject</param>
    /// <returns>true if successful</returns>
    //[Obsolete("use ConfirmTradeAsync")]
    public async Task<bool> ConfirmTrade(Dictionary<string, string> trades, bool accept)
    {
        if (string.IsNullOrEmpty(Session.AccessToken) == true)
        {
            return false;
        }

        long servertime = (CurrentTime + Authenticator.ServerTimeDiff) / 1000L;

        Authenticator.SteamData.ThrowIsNull();
        var ids = JsonSerializer
            .Deserialize(Authenticator.SteamData, SteamJsonContext.Default.SteamConvertSteamDataJsonStruct)
            ?.IdentitySecret;
        ids.ThrowIsNull();

        var conf = accept ? "accept" : "reject";
        // conf -> accept ? "accept" : "reject"
        var timehash = CreateTimeHash(servertime, conf, ids);

        var data = new NameValueCollection()
        {
            { "op", accept ? "allow" : "cancel" },
            { "p", Authenticator.DeviceId },
            { "a", Session.SteamID.ToString() },
            { "k", timehash },
            { "t", servertime.ToString() },
            { "m", "react" },
            { "tag", conf },
        };

        //var multiData = new NameValueCollection();
        foreach (var item in trades)
        {
            data.Add("cid[]", HttpUtility.UrlEncode(item.Key));
            data.Add("ck[]", HttpUtility.UrlEncode(item.Value));
        }
        try
        {
            // https://steamcommunity.com/mobileconf/multiajaxop?a=SteamID&tag=list&m=react&t=servertime&p=EncodeURL(deviceID)&k=EncodeURL(timehash)&op={accept ? "allow" : "cancel"}
            // post 请求
            // data 为 NameValueCollection 
            // 现在可单条请求处理多个交易 循环以下代码添加批量的 cid 和 ck 即可
            // data.Add("cid[]", id);
            // data.Add("ck[]", key);
            string response = await RequestAsync<string>(COMMUNITY_BASE + "/mobileconf/multiajaxop", "POST", data);

            if (string.IsNullOrEmpty(response) == true)
            {
                Error = "Blank response";
                return false;
            }

            var jsonobj = JsonSerializer.Deserialize(response, SteamJsonContext.Default.SteamGetConfirmationJsonStruct);

            if (jsonobj == null || jsonobj.Success == false)
            {
                Error = "Failed";
                return false;
            }

            //if (Session.Confirmations?.Ids != null)
            //{
            //    lock (Session.Confirmations)
            //    {
            //        foreach (var item in trades.Where(item => Session.Confirmations.Ids.Contains(item.Key) == true))
            //        {
            //            Session.Confirmations.Ids.Remove(item.Key);
            //        }
            //    }
            //}

            return true;
        }
        catch (WinAuthInvalidSteamRequestException ex)
        {
            Log.Error(nameof(SteamClient), ex, nameof(ConfirmTrade));
#if DEBUG
            Error = ex.Message + Environment.NewLine + ex.StackTrace;
#else
            Error = ex.Message;
#endif
            return false;
        }
    }

    public async Task CheckCookiesAsync(CookieContainer? cookies, string? language)
    {
        // get session
        if (cookies == null || cookies.Count == 0)
        {
            cookies = new CookieContainer();
            cookies.Add(new Uri(COMMUNITY_BASE + "/"), new Cookie("mobileClientVersion", "3067969+%282.1.3%29"));
            cookies.Add(new Uri(COMMUNITY_BASE + "/"), new Cookie("mobileClient", "android"));
            cookies.Add(new Uri(COMMUNITY_BASE + "/"), new Cookie("steamid", ""));
            cookies.Add(new Uri(COMMUNITY_BASE + "/"), new Cookie("steamLogin", ""));
            cookies.Add(new Uri(COMMUNITY_BASE + "/"), new Cookie("Steam_Language", language));
            cookies.Add(new Uri(COMMUNITY_BASE + "/"), new Cookie("dob", ""));

            var headers = new NameValueCollection
            {
                { "X-Requested-With", "com.valvesoftware.android.steam.community" },
            };

            _ = await RequestAsync<string>(
                "https://steamcommunity.com/login?oauth_client_id=DE45CD61&oauth_scope=read_profile%20write_profile%20read_client%20write_client",
                "GET", null, cookies, headers);
        }
    }

    public async Task<string> GetRSAKeyAsync(string donotache, string username, CookieContainer? cookies)
    {
        NameValueCollection data = new()
        {
            { "donotache", donotache },
            { "username", username }
        };
        return await RequestAsync<string>(COMMUNITY_BASE + "/login/getrsakey", "POST", data, cookies);
    }

    public async Task<string> AddAuthenticatorAsync(string? steamid, string authenticator_time, string? device_identifier, string access_token, string authenticator_type = "1", string sms_phone_id = "1")
    {
        var data = new NameValueCollection();
        data.Add("steamid", steamid);
        data.Add("authenticator_time", authenticator_time);
        data.Add("authenticator_type", authenticator_type);
        data.Add("device_identifier", device_identifier);
        data.Add("sms_phone_id", sms_phone_id);
        const string url_ITwoFactorService_AddAuthenticator_v0001 = "/ITwoFactorService/AddAuthenticator/v1";
        return await RequestAsync<string>(
            WEBAPI_BASE + url_ITwoFactorService_AddAuthenticator_v0001 + $"/?access_token={access_token}",
            "POST", data);
    }

    public async Task<string> FinalizeAddAuthenticatorAsync(string? steamid, string? activation_code, string authenticator_code, string authenticator_time, string access_token, string validate_sms_code = "1")
    {
        var data = new NameValueCollection();
        data.Add("steamid", steamid);
        data.Add("activation_code", activation_code);
        data.Add("validate_sms_code", validate_sms_code);
        data.Add("authenticator_code", authenticator_code);
        data.Add("authenticator_time", authenticator_time);
        return await RequestAsync<string>(
                WEBAPI_BASE + $"/ITwoFactorService/FinalizeAddAuthenticator/v1/?access_token={access_token}",
                "POST",
                data);
    }

    public async Task<string> GetUserCountry(string access_token, string steamid)
    {
        var data = new NameValueCollection();
        data.Add("steamid", steamid);
        return await RequestAsync<string>(WEBAPI_BASE + $"/IUserAccountService/GetUserCountry/v1?access_token={access_token}",
                "POST", data);
    }

    public async Task<string> AddPhoneNumberAsync(string phone_number, string? contury_code, string access_token)
    {
        var data = new NameValueCollection();
        data.Add("phone_number", phone_number);
        data.Add("phone_country_code", contury_code);
        return await RequestAsync<string>(
                    WEBAPI_BASE + $"/IPhoneService/SetAccountPhoneNumber/v1?access_token={access_token}", "POST",
                    data);
    }

    public async Task<string> AccountWaitingForEmailConfirmation(string access_token)
    {
        return await RequestAsync<string>(
            WEBAPI_BASE + $"/IPhoneService/IsAccountWaitingForEmailConfirmation/v1?access_token={access_token}",
            "POST");
    }

    public async Task<string> SendPhoneVerificationCode(string access_token)
    {
        return await RequestAsync<string>(
                WEBAPI_BASE + $"/IPhoneService/SendPhoneVerificationCode/v1?access_token={access_token}",
                "POST");
    }

    public async Task<string> RemoveAuthenticatorAsync(string? revocation_code, string steamguard_scheme, string access_token, string revocation_reason = "1")
    {
        revocation_code.ThrowIsNull("恢复代码为null");
        var data = new NameValueCollection
        {
            { "revocation_code", revocation_code },
            { "revocation_reason", "1" },
            { "steamguard_scheme", steamguard_scheme }
        };
        return await RequestAsync<string>(WEBAPI_BASE + $"/ITwoFactorService/RemoveAuthenticator/v1?access_token={access_token}", "POST",
                data);
    }

    public async Task<CTwoFactor_RemoveAuthenticatorViaChallengeStart_Response> RemoveAuthenticatorViaChallengeStartSync(string access_token)
    {
        var base64string = ConvertBase64String(new CTwoFactor_RemoveAuthenticatorViaChallengeStart_Request());
        var data = new NameValueCollection
        {
            { "input_protobuf_encoded", base64string }
        };
        return await RequestAsync<CTwoFactor_RemoveAuthenticatorViaChallengeStart_Response>(WEBAPI_BASE + $"/ITwoFactorService/RemoveAuthenticatorViaChallengeStart/v1?access_token={access_token}", "POST", data, isProtobuf: true);
    }

    public async Task<CTwoFactor_RemoveAuthenticatorViaChallengeContinue_Response> RemoveAuthenticatorViaChallengeContinueSync(string? sms_code, string access_token, bool generate_new_token = true)
    {
        var base64string = ConvertBase64String(new CTwoFactor_RemoveAuthenticatorViaChallengeContinue_Request
        {
            sms_code = sms_code,
            generate_new_token = generate_new_token
        });
        var data = new NameValueCollection
        {
            { "input_protobuf_encoded", base64string }
        };
        return await RequestAsync<CTwoFactor_RemoveAuthenticatorViaChallengeContinue_Response>(WEBAPI_BASE + $"/ITwoFactorService/RemoveAuthenticatorViaChallengeContinue/v1?access_token={access_token}", "POST", data, isProtobuf: true);
    }

    public async Task<string> TwoFAQueryTime()
    {
        return await RequestAsync<string>(SYNC_URL, "POST", null, null, null, SYNC_TIMEOUT);
    }

    // /// <summary>
    // /// Get details for an individual Confirmation
    // /// </summary>
    // /// <param name="trade">trade Confirmation</param>
    // /// <returns>html string of details</returns>
    // //[Obsolete("use GetConfirmationDetailsAsync")]
    // //[Obsolete("0 references", true)]
    // public string GetConfirmationDetails(Confirmation trade)
    // {
    //     // build details URL
    //     string url = COMMUNITY_BASE + "/mobileconf/details/" + trade.Id + "?" + ConfirmationsQuery;
    //
    //     string response = GetString(url);
    //     if (!response.Contains("success", StringComparison.OrdinalIgnoreCase))
    //     {
    //         throw new WinAuthInvalidSteamRequestException("Invalid request from steam: " + response);
    //     }
    //     var jsonobj = JsonSerializer.Deserialize(response, SteamJsonContext.Default.SteamGetConfirmationJsonStruct);
    //     jsonobj.ThrowIsNull();
    //     if (jsonobj.Success == true)
    //     {
    //         ConfirmationsHtml.ThrowIsNull();
    //         Regex detailsRegex = ConfirmationDetailsRegex();
    //         var match = detailsRegex.Match(ConfirmationsHtml);
    //         if (match.Success == true)
    //         {
    //             return match.Groups[1].Value + jsonobj.Html + match.Groups[2].Value;
    //         }
    //     }
    //
    //     return $"<html><head></head><body><p>{jsonobj.Html}</p></body></html>";
    // }

    // /// <summary>
    // /// Refresh the login session cookies from the OAuth code
    // /// </summary>
    // /// <returns>true if successful</returns>
    //[Obsolete("use RefreshAsync")]
    // public bool Refresh()
    // {
    //     try
    //     {
    //         var data = new NameValueCollection
    //         {
    //             { "access_token", Session.OAuthToken },
    //         };
    //         string response = GetString(API_GETWGTOKEN, "POST", data);
    //         if (string.IsNullOrEmpty(response) == true)
    //         {
    //             return false;
    //         }
    //
    //         var jsonobj = JsonSerializer.Deserialize(response, SteamJsonContext.Default.SteamRefreshJsonStruct);
    //         jsonobj.ThrowIsNull();
    //         if (jsonobj.Token == string.Empty)
    //         {
    //             return false;
    //         }
    //         var cookieuri = new Uri(COMMUNITY_BASE + "/");
    //         Session.Cookies.Add(cookieuri, new Cookie("steamLogin", Session.SteamId + "||" + jsonobj.Token));
    //
    //         if (jsonobj.TokenSecure == string.Empty)
    //         {
    //             return false;
    //         }
    //         Session.Cookies.Add(cookieuri, new Cookie("steamLoginSecure", Session.SteamId + "||" + jsonobj.TokenSecure));
    //
    //         // perform UMQ login
    //         //response = GetString(API_LOGON, "POST", data);
    //         //var loginresponse = JsonConvert.DeserializeObject<Dictionary<string, object>>(response);
    //         //if (loginresponse.ContainsKey("umqid") == true)
    //         //{
    //         //	this.Session.UmqId = (string)loginresponse["umqid"];
    //         //	if (loginresponse.ContainsKey("message") == true)
    //         //	{
    //         //		this.Session.MessageId = Convert.ToInt32(loginresponse["message"]);
    //         //	}
    //         //}
    //
    //         return true;
    //     }
    //     catch (Exception)
    //     {
    //         return false;
    //     }
    // }
    #endregion

    #region Web Request

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
    async Task<T> RequestAsync<T>(string url, string method, NameValueCollection? data = null,
        CookieContainer? cookies = null, NameValueCollection? headers = null, int timeout = 0, bool isProtobuf = false)
    {
        // create form-encoded data for query or body
        var query = data == null
            ? string.Empty
            : string.Join('&',
                Array.ConvertAll(data.AllKeys,
                    key => string.Format("{0}={1}", HttpUtility.UrlEncode(key), HttpUtility.UrlEncode(data[key]))));
        if (string.Compare(method, "GET", true) == 0)
            url += (!url.Contains('?', StringComparison.CurrentCulture) ? '?' : '&') + query;

        var httpClient = _httpClient;

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
                throw new WinAuthSteamToManyRequestException(Strings.Error_TooManyRequests);
            }

            if (responseMessage.StatusCode != HttpStatusCode.OK)
                throw new WinAuthInvalidRequestException(string.Format("{0}: {1}", (int)responseMessage.StatusCode,
                    responseMessage.RequestMessage));

            if (isProtobuf)
            {
                using var responeStream = await responseMessage.Content.ReadAsStreamAsync();
                var result = Serializer.Deserialize<T>(responeStream);
                return result;
            }
            else
            {
                resultstring = await responseMessage.Content.ReadAsStringAsync();
                return (T)(object)resultstring;
            }

            LogRequest(method, url, cookies, data, resultstring);
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

    /// <summary>
    /// Log an exception from a Request
    /// </summary>
    /// <param name="method">Get or POST</param>
    /// <param name="url">Request URL</param>
    /// <param name="cookies">cookie container</param>
    /// <param name="request">Request data</param>
    /// <param name="ex">Thrown exception</param>
    [Conditional("DEBUG")]
    //[Obsolete("use LogException(string, string, CookieContainer?, IReadOnlyDictionary{string, string}?, Exception)")]
    static void LogException(string? method, string url, CookieContainer? cookies, NameValueCollection? request, Exception ex)
    {
        return;

        //StringBuilder data = new StringBuilder();
        //if (cookies != null)
        //{
        //    foreach (Cookie cookie in cookies.GetCookies(new Uri(url)))
        //    {
        //        if (data.Length == 0)
        //        {
        //            data.Append("Cookies:");
        //        }
        //        else
        //        {
        //            data.Append("&");
        //        }
        //        data.Append(cookie.Name + "=" + cookie.Value);
        //    }
        //    data.Append(" ");
        //}

        //if (request != null)
        //{
        //    foreach (var key in request.AllKeys)
        //    {
        //        if (data.Length == 0)
        //        {
        //            data.Append("Req:");
        //        }
        //        else
        //        {
        //            data.Append("&");
        //        }
        //        data.Append(key + "=" + request[key]);
        //    }
        //    data.Append(" ");
        //}
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
    //[Obsolete("use LogRequest(string, string, CookieContainer?, IReadOnlyDictionary{string, string}?, string)")]
    static void LogRequest(string? method, string url, CookieContainer? cookies, NameValueCollection? request, string? response)
    {
        return;

        //StringBuilder data = new StringBuilder();
        //if (cookies != null)
        //{
        //    foreach (Cookie cookie in cookies.GetCookies(new Uri(url)))
        //    {
        //        if (data.Length == 0)
        //        {
        //            data.Append("Cookies:");
        //        }
        //        else
        //        {
        //            data.Append("&");
        //        }
        //        data.Append(cookie.Name + "=" + cookie.Value);
        //    }
        //    data.Append(" ");
        //}

        //if (request != null)
        //{
        //    foreach (var key in request.AllKeys)
        //    {
        //        if (data.Length == 0)
        //        {
        //            data.Append("Req:");
        //        }
        //        else
        //        {
        //            data.Append("&");
        //        }
        //        data.Append(key + "=" + request[key]);
        //    }
        //    data.Append(" ");
        //}
    }

    #endregion

    #region ToolMethod

    static string ConvertBase64String<T>(T obj)
    {
        using var stream = new MemoryStream();
        Serializer.Serialize(stream, obj);
        var base64string = stream.ToArray().Base64Encode();
        return base64string;
    }

    /// <summary>
    /// Stop the current poller
    /// </summary>
    protected void PollConfirmationsStop()
    {
        // kill any existing poller
        if (_pollerCancellation != null)
        {
            _pollerCancellation.Cancel();
            _pollerCancellation = null;
        }
    }

    /// <summary>
    /// Create the hash needed for the confirmations query string
    /// </summary>
    /// <param name="time">current time</param>
    /// <param name="tag">tag</param>
    /// <param name="secret">identity secret</param>
    /// <returns>hash string</returns>
    static string CreateTimeHash(long time, string tag, string secret)
    {
        byte[] b64secret = Base64Extensions.Base64DecodeToByteArray(secret);

        int bufferSize = 8;
        if (string.IsNullOrEmpty(tag) == false)
        {
            bufferSize += Math.Min(32, tag.Length);
        }
        byte[] buffer = new byte[bufferSize];

        byte[] timeArray = BitConverter.GetBytes(time);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(timeArray);
        }
        Array.Copy(timeArray, buffer, 8);
        if (string.IsNullOrEmpty(tag) == false)
        {
            Array.Copy(Encoding.UTF8.GetBytes(tag), 0, buffer, 8, bufferSize - 8);
        }

        var hmac = new HMACSHA1(b64secret);
        byte[] hash = hmac.ComputeHash(buffer);

        return Convert.ToBase64String(hash, Base64FormattingOptions.None);
    }

    string? GetSelfIconUrlFromConfirmationDetails(string html)
    {
        var regex = GetSelfIconUrlFromConfirmationDetailsRegex().Match(html);
        var result = regex.Groups[1].Value;
        return result.Insert(result.IndexOf(".jpg", StringComparison.Ordinal), "_full");
    }

    ///// <summary>
    ///// Perform a UMQ login
    ///// </summary>
    ///// <returns></returns>
    ////[Obsolete("use UmqLoginAsync")]
    //[Obsolete("0 references", true)]
    //bool UmqLogin()
    //{
    //    if (IsLoggedIn() == false)
    //    {
    //        return false;
    //    }

    //    var data = new NameValueCollection();
    //    data.Add("access_token", this.Session.OAuthToken);
    //    var response = GetString(API_LOGON, "POST", data);
    //    var loginresponse = JsonConvert.DeserializeObject<Dictionary<string, object>>(response);
    //    if (loginresponse.ContainsKey("umqid") == true)
    //    {
    //        Session.UmqId = (string)loginresponse["umqid"];
    //        if (loginresponse.ContainsKey("message") == true)
    //        {
    //            Session.MessageId = Convert.ToInt32(loginresponse["message"]);
    //        }

    //        return true;
    //    }

    //    return false;
    //}

    //[Obsolete("0 references", true)]
    //static string SelectTokenValueStr(JObject obj, string path)
    //{
    //    var value = obj.SelectToken(path)?.Value<string>();
    //    return value.ThrowIsNull(path);
    //}

    //[Obsolete("0 references", true)]
    //static byte[] StringToByteArray(JObject obj, string path)
    //{
    //    return StringToByteArray(SelectTokenValueStr(obj, path));
    //}

    #endregion

    #region GeneratedRegex

    // /// <summary>
    // /// Regular expressions for trade confirmations
    // /// </summary>
    // static readonly Regex _tradesRegex = TradesRegexRegex();
    // static readonly Regex _tradeConfidRegex = TradeConfidRegex();
    // static readonly Regex _tradeKeyRegex = TradeKeyRegexRegex();
    // static readonly Regex _tradePlayerRegex = TradePlayerRegex();
    // static readonly Regex _tradeDetailsRegex = TtradeDetailsRegex();
    //
    // [GeneratedRegex("\"mobileconf_list_entry\"(.*?)>(.*?)\"mobileconf_list_entry_sep\"", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    // private static partial Regex TradesRegexRegex();
    //
    // [GeneratedRegex("data-confid\\s*=\\s*\"([^\"]+)\"", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    // private static partial Regex TradeConfidRegex();
    //
    // [GeneratedRegex("data-key\\s*=\\s*\"([^\"]+)\"", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    // private static partial Regex TradeKeyRegexRegex();
    //
    // [GeneratedRegex("\"mobileconf_list_entry_icon\"(.*?)src=\"([^\"]+)\"", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    // private static partial Regex TradePlayerRegex();
    //
    // [GeneratedRegex("\"mobileconf_list_entry_description\".*?<div>([^<]*)</div>[^<]*<div>([^<]*)</div>[^<]*<div>([^<]*)</div>[^<]*</div>", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    // private static partial Regex TtradeDetailsRegex();

    // [GeneratedRegex("(.*<body[^>]*>\\s*<div\\s+class=\"[^\"]+\">).*(</div>.*?</body>\\s*</html>)", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    // private static partial Regex ConfirmationDetailsRegex();

    [GeneratedRegex("<div class=\"tradeoffer_items_header\">.*?<div class=\"tradeoffer_item_list\">(.*?)<div style=\"clear: left;\"></div>", RegexOptions.Singleline)]
    private static partial Regex ConfirmationItemImageUrlsRegex();

    [GeneratedRegex("<img src=\"(.*?)\"")]
    private static partial Regex ConfirmationItemImageUrlsGetRegex();

    [GeneratedRegex("<div class=\"tradeoffer_items primary\">.*?<img src=\"(.*?)\"", RegexOptions.Singleline)]
    private static partial Regex GetSelfIconUrlFromConfirmationDetailsRegex();
    #endregion

}