﻿/*
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

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Net.Http;
using Org.BouncyCastle.Asn1.Ocsp;

#if NETFX_4
using System.Runtime.Serialization;
using System.Threading.Tasks;
#endif

namespace WinAuth
{
    /// <summary>
    /// SteamClient for logging and getting/accepting/rejecting trade confirmations
    /// </summary>
    public class SteamClient : IDisposable
    {
        /// <summary>
        /// URLs for all mobile services
        /// </summary>
        private const string COMMUNITY_DOMAIN = "steamcommunity.com";
        private const string COMMUNITY_BASE = "https://" + COMMUNITY_DOMAIN;
        private const string WEBAPI_BASE = "https://api.steampowered.com";
        private const string API_GETWGTOKEN = WEBAPI_BASE + "/IMobileAuthService/GetWGToken/v0001";
        private const string API_LOGOFF = WEBAPI_BASE + "/ISteamWebUserPresenceOAuth/Logoff/v0001";
        private const string API_LOGON = WEBAPI_BASE + "/ISteamWebUserPresenceOAuth/Logon/v0001";
        private const string API_POLLSTATUS = WEBAPI_BASE + "/ISteamWebUserPresenceOAuth/PollStatus/v0001";

        /// <summary>
        /// Default mobile user agent
        /// </summary>
        private const string USERAGENT = "Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30";

        /// <summary>
        /// Regular expressions for trade confirmations
        /// </summary>
        private static readonly Regex _tradesRegex = new Regex("\"mobileconf_list_entry\"(.*?)>(.*?)\"mobileconf_list_entry_sep\"", RegexOptions.Singleline | RegexOptions.IgnoreCase);
        private static readonly Regex _tradeConfidRegex = new Regex(@"data-confid\s*=\s*""([^""]+)""", RegexOptions.Singleline | RegexOptions.IgnoreCase);
        private static readonly Regex _tradeKeyRegex = new Regex(@"data-key\s*=\s*""([^""]+)""", RegexOptions.Singleline | RegexOptions.IgnoreCase);
        private static readonly Regex _tradePlayerRegex = new Regex("\"mobileconf_list_entry_icon\"(.*?)src=\"([^\"]+)\"", RegexOptions.Singleline | RegexOptions.IgnoreCase);
        private static readonly Regex _tradeDetailsRegex = new Regex("\"mobileconf_list_entry_description\".*?<div>([^<]*)</div>[^<]*<div>([^<]*)</div>[^<]*<div>([^<]*)</div>[^<]*</div>", RegexOptions.Singleline | RegexOptions.IgnoreCase);

        /// <summary>
        /// Number of Confirmation retries
        /// </summary>
        private const int DEFAULT_CONFIRMATIONPOLLER_RETRIES = 3;

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
            SilentAutoConfirm = 3
        }

        /// <summary>
        /// Hold the Confirmation polling data
        /// </summary>
        public class ConfirmationPoller
        {
            /// <summary>
            /// Seconds between polls
            /// </summary>
            public int Duration;

            /// <summary>
            /// Action for new Confirmation
            /// </summary>
            public PollerAction Action;

            /// <summary>
            /// List of current Confirmations ids
            /// </summary>
            public List<string> Ids;

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
                        "\"action\":" + (int)Action
                    };
                    if (Ids != null)
                    {
                        props.Add("\"ids\":[" + (Ids.Count != 0 ? "\"" + string.Join("\",\"", Ids.ToArray()) + "\"" : string.Empty) + "]");
                    }

                    return "{" + string.Join(",", props.ToArray()) + "}";
                }
            }

            /// <summary>
            /// Create a new ConfirmationPoller from a JSON string
            /// </summary>
            /// <param name="json">JSON string</param>
            /// <returns>new ConfirmationPoller or null</returns>
            public static ConfirmationPoller FromJSON(string json)
            {
                if (string.IsNullOrEmpty(json) == true || json == "null")
                {
                    return null;
                }
                var poller = FromJSON(JsonNode.Parse(json));
                return poller.Duration != 0 ? poller : null;
            }

            /// <summary>
            /// Create a new ConfirmationPoller from a JToken
            /// </summary>
            /// <param name="tokens">existing JKToken</param>
            /// <returns></returns>
            public static ConfirmationPoller FromJSON(JsonNode nodes)
            {
                if (nodes == null)
                {
                    return null;
                }

                var poller = new ConfirmationPoller();

                var token = nodes["duration"];
                if (token != null)
                {
                    poller.Duration = token.GetValue<int>();
                }
                token = nodes["action"];
                if (token != null)
                {
                    poller.Action = (PollerAction)token.GetValue<int>();
                }
                token = nodes["ids"];
                if (token != null)
                {
                    poller.Ids = JsonSerializer.Deserialize<List<string>>(token);
                }

                return poller.Duration != 0 ? poller : null;
            }
        }

        /// <summary>
        /// A class for a single confirmation
        /// </summary>
        public class Confirmation
        {
            public string Id { get; set; }
            public string Key { get; set; }
            public bool Offline { get; set; }
            public bool IsNew { get; set; }
            public string Image { get; set; }
            public string Details { get; set; }
            public string Traded { get; set; }
            public string When { get; set; }
        }

        /// <summary>
        /// Session state to remember logins
        /// </summary>
        public class SteamSession
        {
            /// <summary>
            /// User's steam ID
            /// </summary>
            public string SteamId;

            /// <summary>
            /// Current cookies
            /// </summary>
            public CookieContainer Cookies;

            /// <summary>
            /// Authorization token
            /// </summary>
            public string OAuthToken;

            /// <summary>
            /// UMQ id
            /// </summary>
            public string UmqId;

            /// <summary>
            /// Message id
            /// </summary>
            public int MessageId;

            /// <summary>
            /// Current polling state
            /// </summary>
            public ConfirmationPoller Confirmations;

            /// <summary>
            /// Create Session instance
            /// </summary>
            public SteamSession()
            {
                Clear();
            }

            /// <summary>
            /// Create session instance from existing json data
            /// </summary>
            /// <param name="json">json session data</param>
            public SteamSession(string json) : this()
            {
                if (string.IsNullOrEmpty(json) == false)
                {
                    try
                    {
                        FromJson(json);
                    }
                    catch (Exception)
                    {
                        // invalid json
                    }
                }
            }

            /// <summary>
            /// Clear the session
            /// </summary>
            public void Clear()
            {
                OAuthToken = null;
                UmqId = null;
                Cookies = new CookieContainer();
                Confirmations = null;
            }

            /// <summary>
            /// Get session data that can be saved and imported
            /// </summary>
            /// <returns></returns>
            public override string ToString()
            {
                return "{\"steamid\":\"" + (SteamId ?? string.Empty) + "\","
                    + "\"cookies\":\"" + Cookies.GetCookieHeader(new Uri(COMMUNITY_BASE + "/")) + "\","
                    + "\"oauthtoken\":\"" + (OAuthToken ?? string.Empty) + "\","
                    // + "\"umqid\":\"" + (this.UmqId ?? string.Empty) + "\","
                    + "\"confs\":" + (Confirmations != null ? Confirmations.ToString() : "null")
                    + "}";
            }

            /// <summary>
            /// Convert json data into session
            /// </summary>
            /// <param name="json"></param>
            private void FromJson(string json)
            {
                var tokens = JsonNode.Parse(json);
                var token = tokens["steamid"];
                if (token != null)
                {
                    SteamId = token.ToString();
                }
                token = tokens["cookies"];
                if (token != null)
                {
                    Cookies = new CookieContainer();

                    // Net3.5 has a bug that prepends "." to domain, e.g. ".steamcommunity.com"
                    var uri = new Uri(COMMUNITY_BASE + "/");
                    var match = Regex.Match(token.ToString(), @"([^=]+)=([^;]*);?", RegexOptions.Singleline);
                    while (match.Success == true)
                    {
                        Cookies.Add(uri, new Cookie(match.Groups[1].Value.Trim(), match.Groups[2].Value.Trim()));
                        match = match.NextMatch();
                    }
                }
                token = tokens["oauthtoken"];
                if (token != null)
                {
                    OAuthToken = token.ToString();
                }
                //token = tokens.SelectToken("umqid");
                //if (token != null)
                //{
                //	this.UmqId = token.Value<string>();
                //}
                token = tokens["confs"];
                if (token != null)
                {
                    Confirmations = ConfirmationPoller.FromJSON(token);
                }
            }
        }

        /// <summary>
        /// Login state fields
        /// </summary>
        public bool InvalidLogin;
        public bool RequiresCaptcha;
        public string CaptchaId;
        public string CaptchaUrl;
        public bool Requires2FA;
        public bool RequiresEmailAuth;
        public string EmailDomain;
        public string Error;

        /// <summary>
        /// Current session
        /// </summary>
        public SteamSession Session;

        /// <summary>
        /// Current authenticator
        /// </summary>
        public SteamAuthenticator Authenticator;

        /// <summary>
        /// Saved Html from GetConfirmations used as template for GetDetails
        /// </summary>
        private string ConfirmationsHtml;

        /// <summary>
        /// Query string from GetConfirmations used in GetDetails
        /// </summary>
        private string ConfirmationsQuery;

        /// <summary>
        /// Cancellation token for poller
        /// </summary>
        private CancellationTokenSource _pollerCancellation;

        /// <summary>
        /// Number of Confirmation retries
        /// </summary>
        public int ConfirmationPollerRetries = DEFAULT_CONFIRMATIONPOLLER_RETRIES;

        /// <summary>
        /// Create a new SteamClient
        /// </summary>
        public SteamClient(SteamAuthenticator auth, string session = null)
        {
            Authenticator = auth;
            Session = new SteamSession(session);

            if (Session.Confirmations != null)
            {
                if (IsLoggedIn() == false)
                {
                    Session.Confirmations = null;
                }
                else
                {
                    Task.Factory.StartNew(() =>
                    {
                        Refresh();
                        PollConfirmations(Session.Confirmations);
                    });
                }
            }
        }

        /// <summary>
        /// Finalizer
        /// </summary>
        ~SteamClient()
        {
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

            Session.Clear();
        }

        /// <summary>
        /// Check if user is logged in
        /// </summary>
        /// <returns></returns>
        public bool IsLoggedIn()
        {
            return (Session != null && string.IsNullOrEmpty(Session.OAuthToken) == false);
        }

        /// <summary>
        /// Login to Steam using credentials and optional captcha
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="captchaId"></param>
        /// <param name="captchaText"></param>
        /// <returns>true if successful</returns>
        public bool Login(string username, string password, string captchaId = null, string captchaText = null, string language = null)
        {
            // clear error
            Error = null;

            var data = new NameValueCollection();
            string response;

            if (IsLoggedIn() == false)
            {
                // get session
                if (Session.Cookies.Count == 0)
                {
                    // .Net3.5 has a bug in CookieContainer that prepends a "." to the domain, i.e. ".steamcommunity.com"
                    var cookieuri = new Uri(COMMUNITY_BASE + "/");
                    Session.Cookies.Add(cookieuri, new Cookie("mobileClientVersion", "3067969+%282.1.3%29"));
                    Session.Cookies.Add(cookieuri, new Cookie("mobileClient", "android"));
                    Session.Cookies.Add(cookieuri, new Cookie("steamid", ""));
                    Session.Cookies.Add(cookieuri, new Cookie("steamLogin", ""));
                    Session.Cookies.Add(cookieuri, new Cookie("Steam_Language", string.IsNullOrEmpty(language) ? "english" : language));
                    Session.Cookies.Add(cookieuri, new Cookie("dob", ""));

                    NameValueCollection headers = new NameValueCollection();
                    headers.Add("X-Requested-With", "com.valvesoftware.android.steam.community");

                    response = GetString(COMMUNITY_BASE + "/mobilelogin?oauth_client_id=DE45CD61&oauth_scope=read_profile%20write_profile%20read_client%20write_client", "GET", null, headers);
                }

                // Steam strips any non-ascii chars from username and password
                username = Regex.Replace(username, @"[^\u0000-\u007F]", string.Empty);
                password = Regex.Replace(password, @"[^\u0000-\u007F]", string.Empty);

                // get the user's RSA key
                data.Add("username", username);
                response = GetString(COMMUNITY_BASE + "/mobilelogin/getrsakey", "POST", data);
                var rsaresponse = JsonNode.Parse(response);
                if (rsaresponse["success"].GetValue<bool>() != true)
                {
                    InvalidLogin = true;
                    Error = "Unknown username";
                    return false;
                }

                // encrypt password with RSA key
                RNGCryptoServiceProvider random = new RNGCryptoServiceProvider();
                string encryptedPassword64;
                using (var rsa = new RSACryptoServiceProvider())
                {
                    var passwordBytes = Encoding.ASCII.GetBytes(password);
                    var p = rsa.ExportParameters(false);
                    p.Exponent = StringToByteArray(rsaresponse["publickey_exp"].ToString());
                    p.Modulus = StringToByteArray(rsaresponse["publickey_mod"].ToString());
                    rsa.ImportParameters(p);
                    byte[] encryptedPassword = rsa.Encrypt(passwordBytes, false);
                    encryptedPassword64 = Convert.ToBase64String(encryptedPassword);
                }

                // login request
                data = new NameValueCollection
                {
                    { "password", encryptedPassword64 },
                    { "username", username },
                    { "twofactorcode", Authenticator.CurrentCode },
                    //data.Add("emailauth", string.Empty);
                    { "loginfriendlyname", "#login_emailauth_friendlyname_mobile" },
                    { "captchagid", (string.IsNullOrEmpty(captchaId) == false ? captchaId : "-1") },
                    { "captcha_text", (string.IsNullOrEmpty(captchaText) == false ? captchaText : "enter above characters") },
                    //data.Add("emailsteamid", (string.IsNullOrEmpty(emailcode) == false ? this.SteamId ?? string.Empty : string.Empty));
                    { "rsatimestamp", rsaresponse["timestamp"].ToString() },
                    { "remember_login", "false" },
                    { "oauth_client_id", "DE45CD61" },
                    { "oauth_scope", "read_profile write_profile read_client write_client" },
                    { "donotache", new DateTime().ToUniversalTime().Subtract(new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds.ToString() }
                };
                response = GetString(COMMUNITY_BASE + "/mobilelogin/dologin/", "POST", data);
                Dictionary<string, object> loginresponse = JsonSerializer.Deserialize<Dictionary<string, object>>(response);

                if (loginresponse.ContainsKey("emailsteamid") == true)
                {
                    Session.SteamId = loginresponse["emailsteamid"] as string;
                }

                InvalidLogin = false;
                RequiresCaptcha = false;
                CaptchaId = null;
                CaptchaUrl = null;
                RequiresEmailAuth = false;
                EmailDomain = null;
                Requires2FA = false;

                //以下if语句块待测试
                if (loginresponse.ContainsKey("login_complete") == false || (bool)loginresponse["login_complete"] == false || loginresponse.ContainsKey("oauth") == false)
                {
                    InvalidLogin = true;

                    // require captcha
                    if (loginresponse.ContainsKey("captcha_needed") == true && (bool)loginresponse["captcha_needed"] == true)
                    {
                        RequiresCaptcha = true;
                        CaptchaId = (string)loginresponse["captcha_gid"];
                        CaptchaUrl = COMMUNITY_BASE + "/public/captcha.php?gid=" + CaptchaId;
                    }

                    // require email auth
                    if (loginresponse.ContainsKey("emailauth_needed") == true && (bool)loginresponse["emailauth_needed"] == true)
                    {
                        if (loginresponse.ContainsKey("emaildomain") == true)
                        {
                            var emaildomain = (string)loginresponse["emaildomain"];
                            if (string.IsNullOrEmpty(emaildomain) == false)
                            {
                                EmailDomain = emaildomain;
                            }
                        }
                        RequiresEmailAuth = true;
                    }

                    // require email auth
                    if (loginresponse.ContainsKey("requires_twofactor") == true && (bool)loginresponse["requires_twofactor"] == true)
                    {
                        Requires2FA = true;
                    }

                    if (loginresponse.ContainsKey("message") == true)
                    {
                        Error = (string)loginresponse["message"];
                    }

                    return false;
                }

                // get the OAuth token
                string oauth = (string)loginresponse["oauth"];
                var oauthjson = JsonNode.Parse(oauth);
                Session.OAuthToken = oauthjson["oauth_token"].ToString();
                if (oauthjson["steamid"] != null)
                {
                    Session.SteamId = oauthjson["steamid"].ToString();
                }

                //// perform UMQ login
                //data.Clear();
                //data.Add("access_token", this.Session.OAuthToken);
                //response = GetString(API_LOGON, "POST", data);
                //loginresponse = JsonConvert.DeserializeObject<Dictionary<string, object>>(response);
                //if (loginresponse.ContainsKey("umqid") == true)
                //{
                //	this.Session.UmqId = (string)loginresponse["umqid"];
                //	if (loginresponse.ContainsKey("message") == true)
                //	{
                //		this.Session.MessageId = Convert.ToInt32(loginresponse["message"]);
                //	}
                //}
            }

            return true;
        }

        /// <summary>
        /// Logout of the current session
        /// </summary>
        public void Logout()
        {
            if (string.IsNullOrEmpty(Session.OAuthToken) == false)
            {
                PollConfirmationsStop();

                if (string.IsNullOrEmpty(Session.UmqId) == false)
                {
                    var data = new NameValueCollection
                    {
                        { "access_token", Session.OAuthToken },
                        { "umqid", Session.UmqId }
                    };
                    GetString(API_LOGOFF, "POST", data);
                }
            }

            Clear();
        }

        /// <summary>
        /// Refresh the login session cookies from the OAuth code
        /// </summary>
        /// <returns>true if successful</returns>
        public bool Refresh()
        {
            try
            {
                var data = new NameValueCollection();
                data.Add("access_token", Session.OAuthToken);
                string response = GetString(API_GETWGTOKEN, "POST", data);
                if (string.IsNullOrEmpty(response) == true)
                {
                    return false;
                }

                var json = JsonNode.Parse(response);
                var token = json["response"]["token"];
                if (token == null)
                {
                    return false;
                }

                var cookieuri = new Uri(COMMUNITY_BASE + "/");
                Session.Cookies.Add(cookieuri, new Cookie("steamLogin", Session.SteamId + "||" + token.ToString()));

                token = json["response"]["token_secure"];
                if (token == null)
                {
                    return false;
                }
                Session.Cookies.Add(cookieuri, new Cookie("steamLoginSecure", Session.SteamId + "||" + token.ToString()));

                // perform UMQ login
                //response = GetString(API_LOGON, "POST", data);
                //var loginresponse = JsonConvert.DeserializeObject<Dictionary<string, object>>(response);
                //if (loginresponse.ContainsKey("umqid") == true)
                //{
                //	this.Session.UmqId = (string)loginresponse["umqid"];
                //	if (loginresponse.ContainsKey("message") == true)
                //	{
                //		this.Session.MessageId = Convert.ToInt32(loginresponse["message"]);
                //	}
                //}

                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Perform a UMQ login
        /// </summary>
        /// <returns></returns>
        private bool UmqLogin()
        {
            if (IsLoggedIn() == false)
            {
                return false;
            }

            var data = new NameValueCollection();
            data.Add("access_token", Session.OAuthToken);
            var response = GetString(API_LOGON, "POST", data);
            var loginresponse = JsonSerializer.Deserialize<Dictionary<string, object>>(response);
            if (loginresponse.ContainsKey("umqid") == true)
            {
                Session.UmqId = (string)loginresponse["umqid"];
                if (loginresponse.ContainsKey("message") == true)
                {
                    Session.MessageId = Convert.ToInt32(loginresponse["message"]);
                }

                return true;
            }

            return false;
        }

        /// <summary>
        /// Delegate for Confirmation event
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="newconfirmation">new Confirmation</param>
        /// <param name="action">action to be taken</param>
        public delegate void ConfirmationDelegate(object sender, Confirmation newconfirmation, PollerAction action);

        /// <summary>
        /// Delegate for Confirmation error
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="message">error message</param>
        /// <param name="ex">optional exception</param>
        public delegate void ConfirmationErrorDelegate(object sender, string message, PollerAction action, Exception ex);

        /// <summary>
        /// Event fired for new Confirmation
        /// </summary>
        public event ConfirmationDelegate ConfirmationEvent;

        /// <summary>
        /// Event fired for error on polling
        /// </summary>
        public event ConfirmationErrorDelegate ConfirmationErrorEvent;

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
            Session.Confirmations = null;
        }

        /// <summary>
        /// Start a new poller
        /// </summary>
        /// <param name="poller"></param>
        public void PollConfirmations(ConfirmationPoller poller)
        {
            PollConfirmationsStop();

            if (poller == null || poller.Duration <= 0)
            {
                return;
            }

            if (Session.Confirmations == null)
            {
                Session.Confirmations = new ConfirmationPoller();
            }
            Session.Confirmations = poller;

            _pollerCancellation = new CancellationTokenSource();
            var token = _pollerCancellation.Token;
            Task.Factory.StartNew(() => PollConfirmationsAsync(token), token, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }

        /// <summary>
        /// Confirmation polling task
        /// </summary>
        /// <param name="cancel"></param>
        public async void PollConfirmationsAsync(CancellationToken cancel)
        {
            //lock (this.Session.Confirmations)
            //{
            //	if (this.Session.Confirmations.Ids == null)
            //	{
            //		try
            //		{
            //			// this will update the session
            //			GetConfirmations();
            //		}
            //		catch (InvalidSteamRequestException)
            //		{
            //			// ignore in case of Steam timeout
            //		}
            //	}
            //}

            try
            {
                int retryCount = 0;
                while (!cancel.IsCancellationRequested && Session.Confirmations != null)
                {
                    try
                    {
                        //List<string> currentIds;
                        //lock (this.Session.Confirmations)
                        //{
                        //	currentIds = this.Session.Confirmations.Ids;
                        //}

                        var confs = GetConfirmations();

                        // check for new ids
                        //List<string> newIds;
                        //if (currentIds == null)
                        //{
                        //	newIds = confs.Select(t => t.Id).ToList();
                        //}
                        //else
                        //{
                        //	newIds = confs.Select(t => t.Id).Except(currentIds).ToList();
                        //}

                        // fire events if subscriber
                        if (ConfirmationEvent != null /* && newIds.Count() != 0 */)
                        {
                            var rand = new Random();
                            foreach (var conf in confs)
                            {
                                if (cancel.IsCancellationRequested)
                                {
                                    break;
                                }

                                DateTime start = DateTime.Now;

                                ConfirmationEvent(this, conf, Session.Confirmations.Action);

                                // Issue#339: add a delay for any autoconfs or notifications
                                var delay = CONFIRMATION_EVENT_DELAY + rand.Next(CONFIRMATION_EVENT_DELAY / 2); // delay is 100%-150% of CONFIRMATION_EVENT_DELAY
                                var duration = (int)DateTime.Now.Subtract(start).TotalMilliseconds;
                                if (delay > duration)
                                {
                                    Thread.Sleep(delay - duration);
                                }
                            }
                        }

                        retryCount = 0;
                    }
                    catch (TaskCanceledException)
                    {
                        throw;
                    }
                    catch (Exception ex)
                    {
                        retryCount++;
                        if (retryCount >= ConfirmationPollerRetries)
                        {
                            ConfirmationErrorEvent(this, "Failed to read confirmations", Session.Confirmations.Action, ex);
                        }
                        else
                        {
                            // try and reset the session
                            try
                            {
                                Refresh();
                            }
                            catch (Exception) { }
                        }
                    }

                    if (Session.Confirmations != null)
                    {
                        await Task.Delay(Session.Confirmations.Duration * 60 * 1000, cancel);
                    }
                }
            }
            catch (TaskCanceledException)
            {
            }
        }

        /// <summary>
        /// Get the current trade Confirmations
        /// </summary>
        /// <returns>list of Confirmation objects</returns>
        public List<Confirmation> GetConfirmations()
        {
            long servertime = (SteamAuthenticator.CurrentTime + Authenticator.ServerTimeDiff) / 1000L;

            var jids = JsonNode.Parse(Authenticator.SteamData)["identity_secret"];
            string ids = (jids != null ? jids.ToString() : string.Empty);

            var timehash = CreateTimeHash(servertime, "conf", ids);

            var data = new NameValueCollection();
            data.Add("p", Authenticator.DeviceId);
            data.Add("a", Session.SteamId);
            data.Add("k", timehash);
            data.Add("t", servertime.ToString());
            data.Add("m", "android");
            data.Add("tag", "conf");

            string html = GetString(COMMUNITY_BASE + "/mobileconf/conf", "GET", data);

            // save last html for confirmations details
            ConfirmationsHtml = html;
            ConfirmationsQuery = string.Join("&", Array.ConvertAll(data.AllKeys, key => String.Format("{0}={1}", HttpUtility.UrlEncode(key), HttpUtility.UrlEncode(data[key]))));

            List<Confirmation> trades = new List<Confirmation>();

            // extract the trades
            Match match = _tradesRegex.Match(html);
            while (match.Success)
            {
                var tradeIds = match.Groups[1].Value;

                var trade = new Confirmation();

                var innerMatch = _tradeConfidRegex.Match(tradeIds);
                if (innerMatch.Success)
                {
                    trade.Id = innerMatch.Groups[1].Value;
                }
                innerMatch = _tradeKeyRegex.Match(tradeIds);
                if (innerMatch.Success)
                {
                    trade.Key = innerMatch.Groups[1].Value;
                }

                var traded = match.Groups[2].Value;

                innerMatch = _tradePlayerRegex.Match(traded);
                if (innerMatch.Success)
                {
                    if (innerMatch.Groups[1].Value.IndexOf("offline") != -1)
                    {
                        trade.Offline = true;
                    }
                    trade.Image = innerMatch.Groups[2].Value;
                }

                innerMatch = _tradeDetailsRegex.Match(traded);
                if (innerMatch.Success)
                {
                    trade.Details = innerMatch.Groups[1].Value;
                    trade.Traded = innerMatch.Groups[2].Value;
                    trade.When = innerMatch.Groups[3].Value;
                }

                trades.Add(trade);

                match = match.NextMatch();
            }

            if (Session.Confirmations != null)
            {
                lock (Session.Confirmations)
                {
                    if (Session.Confirmations.Ids == null)
                    {
                        Session.Confirmations.Ids = new List<string>();
                    }
                    foreach (var conf in trades)
                    {
                        conf.IsNew = (Session.Confirmations.Ids.Contains(conf.Id) == false);
                        if (conf.IsNew == true)
                        {
                            Session.Confirmations.Ids.Add(conf.Id);
                        }
                    }
                    var newIds = trades.Select(t => t.Id).ToList();
                    foreach (var confId in Session.Confirmations.Ids.ToList())
                    {
                        if (newIds.Contains(confId) == false)
                        {
                            Session.Confirmations.Ids.Remove(confId);
                        }
                    }
                }
            }

            return trades;
        }

        /// <summary>
        /// Get details for an individual Confirmation
        /// </summary>
        /// <param name="trade">trade Confirmation</param>
        /// <returns>html string of details</returns>
        public string GetConfirmationDetails(Confirmation trade)
        {
            // build details URL
            string url = COMMUNITY_BASE + "/mobileconf/details/" + trade.Id + "?" + ConfirmationsQuery;

            string response = GetString(url);
            if (response.IndexOf("success") == -1)
            {
                throw new InvalidSteamRequestException("Invalid request from steam: " + response);
            }
            if (JsonNode.Parse(response)["success"].GetValue<bool>() == true)
            {
                string html = JsonNode.Parse(response)["html"].ToString();

                Regex detailsRegex = new Regex(@"(.*<body[^>]*>\s*<div\s+class=""[^""]+"">).*(</div>.*?</body>\s*</html>)", RegexOptions.Singleline | RegexOptions.IgnoreCase);
                var match = detailsRegex.Match(ConfirmationsHtml);
                if (match.Success == true)
                {
                    return match.Groups[1].Value + html + match.Groups[2].Value;
                }
            }

            return "<html><head></head><body><p>Cannot load trade confirmation details</p></body></html>";
        }

        /// <summary>
        /// Confirm or reject a specific trade confirmation
        /// </summary>
        /// <param name="id">id of trade</param>
        /// <param name="key">key for trade</param>
        /// <param name="accept">true to accept, false to reject</param>
        /// <returns>true if successful</returns>
        public bool ConfirmTrade(string id, string key, bool accept)
        {
            if (string.IsNullOrEmpty(Session.OAuthToken) == true)
            {
                return false;
            }

            long servertime = (SteamAuthenticator.CurrentTime + Authenticator.ServerTimeDiff) / 1000L;

            var jids = JsonNode.Parse(Authenticator.SteamData)["identity_secret"];
            string ids = (jids != null ? jids.ToString() : string.Empty);
            var timehash = CreateTimeHash(servertime, "conf", ids);

            var data = new NameValueCollection();
            data.Add("op", accept ? "allow" : "cancel");
            data.Add("p", Authenticator.DeviceId);
            data.Add("a", Session.SteamId);
            data.Add("k", timehash);
            data.Add("t", servertime.ToString());
            data.Add("m", "android");
            data.Add("tag", "conf");
            //
            data.Add("cid", id);
            data.Add("ck", key);

            try
            {
                string response = GetString(COMMUNITY_BASE + "/mobileconf/ajaxop", "GET", data);
                if (string.IsNullOrEmpty(response) == true)
                {
                    Error = "Blank response";
                    return false;
                }

                var success = JsonNode.Parse(response)["success"];
                if (success == null || success.GetValue<bool>() == false)
                {
                    Error = "Failed";
                    return false;
                }

                if (Session.Confirmations != null)
                {
                    lock (Session.Confirmations)
                    {
                        if (Session.Confirmations.Ids.Contains(id) == true)
                        {
                            Session.Confirmations.Ids.Remove(id);
                        }
                    }
                }

                return true;
            }
            catch (InvalidSteamRequestException ex)
            {
#if DEBUG
                Error = ex.Message + Environment.NewLine + ex.StackTrace;
#else
				this.Error = ex.Message;
#endif
                return false;
            }
        }

        /// <summary>
        /// Create the hash needed for the confirmations query string
        /// </summary>
        /// <param name="time">current time</param>
        /// <param name="tag">tag</param>
        /// <param name="secret">identity secret</param>
        /// <returns>hash string</returns>
        private static string CreateTimeHash(long time, string tag, string secret)
        {
            byte[] b64secret = Convert.FromBase64String(secret);

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

            HMACSHA1 hmac = new HMACSHA1(b64secret, true);
            byte[] hash = hmac.ComputeHash(buffer);

            return Convert.ToBase64String(hash, Base64FormattingOptions.None);
        }

        #region Web Request

        /// <summary>
        /// Get binary data web request
        /// </summary>
        /// <param name="url">url</param>
        /// <param name="method">GET or POST</param>
        /// <param name="formdata">optional form data</param>
        /// <param name="headers">optional headers</param>
        /// <returns>array of returned data</returns>
        public byte[] GetData(string url, string method = null, NameValueCollection formdata = null, NameValueCollection headers = null)
        {
            return this.Request(url, method ?? "GET", formdata, headers);
        }

        /// <summary>
        /// Get string from web request
        /// </summary>
        /// <param name="url">url</param>
        /// <param name="method">GET or POST</param>
        /// <param name="formdata">optional form data</param>
        /// <param name="headers">optional headers</param>
        /// <returns>string of returned data</returns>
        public string GetString(string url, string method = null, NameValueCollection formdata = null, NameValueCollection headers = null)
        {
            byte[] data = Request(url, method ?? "GET", formdata, headers);
            if (data == null || data.Length == 0)
            {
                return string.Empty;
            }
            else
            {
                return Encoding.UTF8.GetString(data);
            }
        }

        /// <summary>
        /// Make a request to Steam URL
        /// </summary>
        /// <param name="url">url</param>
        /// <param name="method">GET or POST</param>
        /// <param name="formdata">optional form data</param>
        /// <param name="headers">optional headers</param>
        /// <returns>returned data</returns>
        protected byte[] Request(string url, string method, NameValueCollection data, NameValueCollection headers)
        {
            // ensure only one request per account at a time
            lock (this)
            {
                // create form-encoded data for query or body
                string query = (data == null ? string.Empty : string.Join("&", Array.ConvertAll(data.AllKeys, key => String.Format("{0}={1}", HttpUtility.UrlEncode(key), HttpUtility.UrlEncode(data[key])))));
                if (string.Compare(method, "GET", true) == 0)
                {
                    url += (url.IndexOf("?") == -1 ? "?" : "&") + query;
                }

                // call the server
                HttpClientHandler handler = new HttpClientHandler();
                handler.AllowAutoRedirect = true;
                //抓包分析需注释
                handler.AutomaticDecompression = DecompressionMethods.Deflate | DecompressionMethods.GZip;
                handler.MaxAutomaticRedirections = 1000;
                if (this.Session.Cookies != null)
                {
                    handler.UseCookies = true;
                    handler.CookieContainer = this.Session.Cookies;
                }
                using HttpClient httpClient = new HttpClient(handler);
                httpClient.DefaultRequestHeaders.Add("Accept", "text/javascript, text/html, application/xml, text/xml, */*");
                httpClient.DefaultRequestHeaders.Add("Referer", COMMUNITY_BASE);
                httpClient.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30");
                httpClient.Timeout = new TimeSpan(0, 0, 45);
                httpClient.DefaultRequestHeaders.ExpectContinue = false;
                if (headers != null)
                {
                    for (int i = 0; i < headers.Count; i++)
                    {
                        httpClient.DefaultRequestHeaders.Add(headers.AllKeys[i], headers.Get(i));
                    }
                }

                try
                {
                    HttpResponseMessage responseMessage;
                    if (string.Compare(method, "POST", true) == 0)
                    {
                        HttpContent content = new StringContent(query, Encoding.UTF8, "application/x-www-form-urlencoded");
                        content.Headers.ContentLength = query.Length;
                        responseMessage = httpClient.PostAsync(url, content).Result;
                    }
                    else
                    {
                        responseMessage = httpClient.GetAsync(url).Result;
                    }

                    LogRequest(method, url, this.Session.Cookies, data, responseMessage.StatusCode.ToString() + " " + responseMessage.RequestMessage);

                    // OK?
                    if (responseMessage.StatusCode != HttpStatusCode.OK)
                    {
                        throw new InvalidSteamRequestException(string.Format("{0}: {1}", (int)responseMessage.StatusCode, responseMessage.RequestMessage));
                    }

                    // load the response
                    using (MemoryStream ms = new MemoryStream())
                    {
                        byte[] buffer = new byte[4096];
                        int read;
                        while ((read = responseMessage.Content.ReadAsStream().Read(buffer, 0, 4096)) > 0)
                        {
                            ms.Write(buffer, 0, read);
                        }

                        byte[] responsedata = ms.ToArray();

                        LogRequest(method, url, this.Session.Cookies, data, responsedata != null && responsedata.Length != 0 ? Encoding.UTF8.GetString(responsedata) : string.Empty);

                        return responsedata;
                    }
                }
                catch (Exception ex)
                {
                    LogException(method, url, this.Session.Cookies, data, ex);

                    if (ex is WebException && ((WebException)ex).Response != null && ((HttpWebResponse)((WebException)ex).Response).StatusCode == HttpStatusCode.Forbidden)
                    {
                        throw new UnauthorisedSteamRequestException(ex);
                    }
                    throw new InvalidSteamRequestException(ex.Message, ex);
                }
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
        private static void LogException(string method, string url, CookieContainer cookies, NameValueCollection request, Exception ex)
        {
            StringBuilder data = new StringBuilder();
            if (cookies != null)
            {
                foreach (Cookie cookie in cookies.GetCookies(new Uri(url)))
                {
                    if (data.Length == 0)
                    {
                        data.Append("Cookies:");
                    }
                    else
                    {
                        data.Append("&");
                    }
                    data.Append(cookie.Name + "=" + cookie.Value);
                }
                data.Append(" ");
            }

            if (request != null)
            {
                foreach (var key in request.AllKeys)
                {
                    if (data.Length == 0)
                    {
                        data.Append("Req:");
                    }
                    else
                    {
                        data.Append("&");
                    }
                    data.Append(key + "=" + request[key]);
                }
                data.Append(" ");
            }
        }

        /// <summary>
        /// Log a normal response
        /// </summary>
        /// <param name="method">Get or POST</param>
        /// <param name="url">Request URL</param>
        /// <param name="cookies">cookie container</param>
        /// <param name="request">Request data</param>
        /// <param name="response">response body</param>
        private static void LogRequest(string method, string url, CookieContainer cookies, NameValueCollection request, string response)
        {
            StringBuilder data = new StringBuilder();
            if (cookies != null)
            {
                foreach (Cookie cookie in cookies.GetCookies(new Uri(url)))
                {
                    if (data.Length == 0)
                    {
                        data.Append("Cookies:");
                    }
                    else
                    {
                        data.Append("&");
                    }
                    data.Append(cookie.Name + "=" + cookie.Value);
                }
                data.Append(" ");
            }

            if (request != null)
            {
                foreach (var key in request.AllKeys)
                {
                    if (data.Length == 0)
                    {
                        data.Append("Req:");
                    }
                    else
                    {
                        data.Append("&");
                    }
                    data.Append(key + "=" + request[key]);
                }
                data.Append(" ");
            }
        }

        #endregion

        /// <summary>
        /// Convert a hex string into a byte array. E.g. "001f406a" -> byte[] {0x00, 0x1f, 0x40, 0x6a}
        /// </summary>
        /// <param name="hex">hex string to convert</param>
        /// <returns>byte[] of hex string</returns>
        private static byte[] StringToByteArray(string hex)
        {
            int len = hex.Length;
            byte[] bytes = new byte[len / 2];
            for (int i = 0; i < len; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }

        /// <summary>
        /// Convert a byte array into a ascii hex string, e.g. byte[]{0x00,0x1f,0x40,ox6a} -> "001f406a"
        /// </summary>
        /// <param name="bytes">byte array to convert</param>
        /// <returns>string version of byte array</returns>
        private static string ByteArrayToString(byte[] bytes)
        {
            // Use BitConverter, but it sticks dashes in the string
            return BitConverter.ToString(bytes).Replace("-", string.Empty);
        }

        /// <summary>
        /// Our custom exception for the internal Http Request
        /// </summary>
        public class InvalidSteamRequestException : ApplicationException
        {
            public InvalidSteamRequestException(string msg = null, Exception ex = null) : base(msg, ex)
            {
            }
        }

        public class UnauthorisedSteamRequestException : InvalidSteamRequestException
        {
            public UnauthorisedSteamRequestException(Exception ex = null) : base("Unauthorised", ex)
            {
            }
        }
    }
}