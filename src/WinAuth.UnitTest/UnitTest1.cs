using DynamicData;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Net;
using System.Reflection;

namespace WinAuth.UnitTest;

public class Tests
{
#pragma warning disable NUnit1032 // An IDisposable field/property should be Disposed in a TearDown method
    IServiceProvider service;
#pragma warning restore NUnit1032 // An IDisposable field/property should be Disposed in a TearDown method

    //IRandomGetUserAgentService RandomUserAgentService => service.GetRequiredService<IRandomGetUserAgentService>();

    [SetUp]
    public void Setup()
    {
        var services = new ServiceCollection();
        services.AddLogging(l => l.AddProvider(NullLoggerProvider.Instance));
        //services.AddSingleton<IRandomGetUserAgentService, ConsoleRandomGetUserAgentServiceImpl>();
        service = services.BuildServiceProvider();
        Ioc.ConfigureServices(service);
    }

    [Test]
    public void SteamSessionCookiesRoundTrip()
    {
        var session = new SteamClient.SteamSession
        {
            SteamID = 76561198000000000,
            AccessToken = "synthetic-access-token",
            RefreshToken = "synthetic-refresh-token",
            SessionID = string.Empty,
            Language = "schinese",
        };

        var cookies = session.GetCookies().GetCookies(new Uri("https://steamcommunity.com/"));
        var restored = new SteamClient.SteamSession(session.ToString());

        Assert.Multiple(() =>
        {
            Assert.That(cookies["steamLoginSecure"]?.Value, Is.EqualTo("76561198000000000%7C%7Csynthetic-access-token"));
            Assert.That(cookies["Steam_Language"]?.Value, Is.EqualTo("schinese"));
            Assert.That(session.SessionID, Has.Length.EqualTo(32));
            Assert.That(cookies["sessionid"]?.Value, Is.EqualTo(session.SessionID));
            Assert.That(restored.SteamID, Is.EqualTo(session.SteamID));
            Assert.That(restored.AccessToken, Is.EqualTo(session.AccessToken));
            Assert.That(restored.RefreshToken, Is.EqualTo(session.RefreshToken));
            Assert.That(restored.SessionID, Is.EqualTo(session.SessionID));
        });
    }

    [Test]
    public void SteamSessionSetReplacesCookiesAndDisposesPreviousTransport()
    {
        var authenticator = new SteamAuthenticator();
        using var client = authenticator.GetClient();
        var previousTransport = GetSteamTransport(client);

        client.SessionSet(CreateSteamSession("current").ToString(), "schinese");

        Assert.Throws<ObjectDisposedException>(() => previousTransport.Timeout = TimeSpan.FromSeconds(45));
        var cookies = GetSteamCookies(client).GetCookies(new Uri("https://steamcommunity.com/"));
        Assert.Multiple(() =>
        {
            Assert.That(cookies["steamLoginSecure"]?.Value, Is.EqualTo("76561198000000000%7C%7Ccurrent"));
            Assert.That(cookies["Steam_Language"]?.Value, Is.EqualTo("schinese"));
            Assert.That(cookies["sessionid"]?.Value, Is.EqualTo(client.Session?.SessionID));
        });

        var authenticatedTransport = GetSteamTransport(client);
        client.SessionSet();
        Assert.Throws<ObjectDisposedException>(() => authenticatedTransport.Timeout = TimeSpan.FromSeconds(45));
        Assert.That(GetSteamCookies(client).Count, Is.Zero);
    }

    [TestCase(false)]
    [TestCase(true)]
    public void SteamGetClientPreservesInstalledSessionAndTransport(bool remember)
    {
        var authenticator = new SteamAuthenticator();
        using var client = authenticator.GetClient();
        client.SessionSet(CreateSteamSession("current").ToString(), "schinese");
        authenticator.SessionData = remember ? CreateSteamSession("stale").ToString() : null;
        var transport = GetSteamTransport(client);

        var current = authenticator.GetClient("schinese");

        Assert.Multiple(() =>
        {
            Assert.That(current, Is.SameAs(client));
            Assert.That(GetSteamTransport(current), Is.SameAs(transport));
            Assert.That(current.Session?.AccessToken, Is.EqualTo("current"));
        });

        Assert.That(authenticator.GetClient(), Is.SameAs(client));
        Assert.That(GetSteamTransport(client), Is.SameAs(transport));
        authenticator.GetClient("english");
        Assert.That(client.Session?.AccessToken, Is.EqualTo("current"));
        Assert.That(GetSteamCookies(client).GetCookies(new Uri("https://steamcommunity.com/"))["Steam_Language"]?.Value,
            Is.EqualTo("english"));
        Assert.Throws<ObjectDisposedException>(() => transport.Timeout = TimeSpan.FromSeconds(45));
    }

    [Test]
    public void SteamGetClientLoadsSavedSessionWhenCurrentSessionIsBlank()
    {
        var authenticator = new SteamAuthenticator
        {
            SessionData = CreateSteamSession("saved").ToString(),
        };

        using var client = authenticator.GetClient("schinese");

        Assert.That(client.Session?.AccessToken, Is.EqualTo("saved"));
        Assert.That(GetSteamCookies(client).GetCookies(new Uri("https://steamcommunity.com/"))["steamLoginSecure"]?.Value,
            Is.EqualTo("76561198000000000%7C%7Csaved"));
    }

    [Test]
    public void SteamGetClientReplacesDisposedClientWithoutReloadingStaleSavedSession()
    {
        var authenticator = new SteamAuthenticator();
        var previous = authenticator.GetClient();
        previous.SessionSet(CreateSteamSession("current").ToString(), "schinese");
        authenticator.SessionData = CreateSteamSession("stale").ToString();
        var transport = GetSteamTransport(previous);

        previous.Dispose();
        previous.Dispose();

        Assert.Throws<ObjectDisposedException>(() => transport.Timeout = TimeSpan.FromSeconds(45));
        Assert.Throws<ObjectDisposedException>(() => previous.SessionSet());
        using var current = authenticator.GetClient();
        Assert.Multiple(() =>
        {
            Assert.That(current, Is.Not.SameAs(previous));
            Assert.That(current.Session?.AccessToken, Is.EqualTo("current"));
            Assert.That(current.Session?.Language, Is.EqualTo("schinese"));
        });
    }

    [Test]
    public void SteamLogoutClearsSessionAndAuthenticatedTransport()
    {
        var authenticator = new SteamAuthenticator();
        using var client = authenticator.GetClient();
        client.SessionSet(CreateSteamSession("current").ToString());
        var transport = GetSteamTransport(client);

        client.Logout();

        Assert.That(client.Session, Is.Null);
        Assert.That(client.IsLoggedIn(), Is.False);
        Assert.Throws<ObjectDisposedException>(() => transport.Timeout = TimeSpan.FromSeconds(45));
        Assert.That(authenticator.GetClient(), Is.SameAs(client));
        Assert.That(GetSteamCookies(client).Count, Is.Zero);
    }

    static SteamClient.SteamSession CreateSteamSession(string accessToken) => new()
    {
        SteamID = 76561198000000000,
        AccessToken = accessToken,
        RefreshToken = "synthetic-refresh-token",
    };

    static HttpClient GetSteamTransport(SteamClient client) =>
        (HttpClient)typeof(SteamClient).GetField("_httpClient", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(client)!;

    static CookieContainer GetSteamCookies(SteamClient client)
    {
        var handler = typeof(HttpMessageInvoker).GetField("_handler", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(GetSteamTransport(client))!;
        return (CookieContainer)handler.GetType().GetProperty("CookieContainer")!.GetValue(handler)!;
    }

    [TestCase(false)]
    [TestCase(true)]
    public void SteamSecretSerializationUsesOnlyExplicitlyRememberedSession(bool remember)
    {
        var authenticator = new SteamAuthenticator
        {
            SecretKey = new byte[] { 1, 2, 3 },
            Serial = "synthetic-serial",
            DeviceId = "android:synthetic-device",
            SteamData = "{}",
        };
        using var client = authenticator.GetClient();
        client.SessionSet(CreateSteamSession("current").ToString());
        var savedSession = remember ? CreateSteamSession("saved").ToString() : null;
        authenticator.SessionData = savedSession;

        var serialized = authenticator.SecretData!;
        var restored = new SteamAuthenticator { SecretData = serialized };
        using var restoredClient = restored.GetClient();

        Assert.Multiple(() =>
        {
            Assert.That(authenticator.SessionData, Is.EqualTo(savedSession));
            Assert.That(restored.SessionData, Is.EqualTo(savedSession));
            Assert.That(restoredClient.Session?.AccessToken, Is.EqualTo(remember ? "saved" : null));
        });
    }

    [Test]
    public void SteamAuthenticatorDoesNotRequireRememberedLoginToRemainValid()
    {
        var authenticator = new SteamAuthenticator
        {
            SecretKey = new byte[] { 1, 2, 3 },
            Serial = "synthetic-serial",
            DeviceId = "android:synthetic-device",
            SteamData = "{}",
            SessionData = null,
        };
        Assert.That(((BD.Common.Models.Abstractions.IExplicitHasValue)authenticator).ExplicitHasValue(), Is.True);
        authenticator.GetClient().Dispose();
    }

    //[Test]
    //public async Task SteamAuthenticatorTest()
    //{
    //    SteamAuthenticator steamAuthenticator = new();
    //    SteamAuthenticator.EnrollState enrollState = new()
    //    {
    //        Language = "zh-Hans",
    //        Username = "hhhhh",
    //        Password = "hhhhh"
    //    };
    //    await steamAuthenticator.EnrollAsync(enrollState);
    //    //while (enrollState.RequiresCaptcha || enrollState.RequiresEmailAuth || enrollState.RequiresActivation)
    //    //{
    //    //    if (enrollState.RequiresCaptcha)
    //    //    {
    //    //        enrollState.CaptchaText = "1234";
    //    //        await steamAuthenticator.EnrollAsync(enrollState);
    //    //    }
    //    //    if (enrollState.RequiresEmailAuth)
    //    //    {
    //    //        enrollState.EmailAuthText = "M6B9P";
    //    //        await steamAuthenticator.EnrollAsync(enrollState);
    //    //    }
    //    //    if (enrollState.RequiresActivation)
    //    //    {
    //    //        enrollState.ActivationCode = "29231";
    //    //        await steamAuthenticator.EnrollAsync(enrollState);
    //    //    }
    //    //}
    //    TestContext.WriteLine(enrollState.Success.ToString());
    //}

    //[Test]
    //public void SteamClientTest()
    //{
    //    //SteamAuthenticator steamAuthenticator = new SteamAuthenticator();
    //    //string? session = null;
    //    //SteamClient client = new SteamClient(steamAuthenticator, session);
    //    //var success = client.Login("hhhh", "hhh");
    //    //TestContext.WriteLine($"{success}");
    //    //RandomUserAgentService.GetUserAgent();
    //}

    //[Test]
    //public void ImportTest()
    //{
    //    string privateKey = "11111";

    //    GoogleAuthenticator auth = new GoogleAuthenticator();
    //    auth.Enroll(privateKey);

    //    string key = WinAuth.Base32.GetInstance().Encode(auth.SecretKey!);
    //    var text1 = Regex.Replace(key, ".{3}", "$0 ").Trim();
    //    var code = auth.CurrentCode;

    //    if (auth.ServerTimeDiff == 0L)
    //    {
    //        TestContext.WriteLine("无法连接到Google服务器");
    //    }

    //    TestContext.WriteLine($"{text1}\r\n{code}");
    //}
}