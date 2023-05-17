using DynamicData;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System.Collections.Concurrent;

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

        [Test]
        public async Task Test1()
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
                    enrollState.EmailAuthText = "1234";
                    await steamAuthenticator.EnrollAsync(enrollState);
                }
                if (enrollState.RequiresActivation)
                {
                    enrollState.ActivationCode = "1234";
                    await steamAuthenticator.EnrollAsync(enrollState);
                }
            }
            TestContext.WriteLine(enrollState.Success.ToString());
        }

        //[Test]
        //public void Test2()
        //{
        //    TestContext.WriteLine(nameof(WinAuth));
        //}
    }
}