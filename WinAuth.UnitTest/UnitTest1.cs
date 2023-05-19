using DynamicData;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Text.Json;

namespace WinAuth.UnitTest
{
    public class Tests
    {
        IServiceProvider service;

        [SetUp]
        public void Setup()
        {
            var services = new ServiceCollection();
            services.AddLogging(l => l.AddProvider(NullLoggerProvider.Instance));
            service = services.BuildServiceProvider();
            Ioc.ConfigureServices(service);
        }

        //[Test]
        public async Task SteamAuthenticatorTest()
        {
            SteamAuthenticator steamAuthenticator = new SteamAuthenticator();
            SteamAuthenticator.EnrollState enrollState = new SteamAuthenticator.EnrollState() { Language = "zh-Hans" };
            enrollState.Username = "hhhh";
            enrollState.Password = "hhhh";
            await steamAuthenticator.EnrollAsync(enrollState);
            while (enrollState.RequiresCaptcha || enrollState.RequiresEmailAuth || enrollState.RequiresActivation)
            {
                if (enrollState.RequiresCaptcha)
                {
                    enrollState.CaptchaText = "1234";
                    await steamAuthenticator.EnrollAsync(enrollState);
                }
                if (enrollState.RequiresEmailAuth)
                {
                    enrollState.EmailAuthText = "M6B9P";
                    await steamAuthenticator.EnrollAsync(enrollState);
                }
                if (enrollState.RequiresActivation)
                {
                    enrollState.ActivationCode = "29231";
                    await steamAuthenticator.EnrollAsync(enrollState);
                }
            }
            TestContext.WriteLine(enrollState.Success.ToString());
        }

        [Test]
        public void SteamClientTest()
        {
            //SteamAuthenticator steamAuthenticator = new SteamAuthenticator();
            //string? session = null;
            //SteamClient client = new SteamClient(steamAuthenticator, session);
            //var success = client.Login("hhhh", "hhh");
            //TestContext.WriteLine($"{success}");
        }

    }
}