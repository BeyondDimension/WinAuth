using DynamicData;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Text.Json;

namespace WinAuth.UnitTest;

public class Tests
{
    IServiceProvider service;

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