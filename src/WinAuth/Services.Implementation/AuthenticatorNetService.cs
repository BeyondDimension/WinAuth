// ReSharper disable once CheckNamespace
using System.Net.Http.Client;
using Microsoft.Extensions.Options;

namespace BD.WTTS.Models;

public static class AuthenticatorNetService
{
    private static readonly IHttpClientFactory _httpClientFactory = Ioc.Get<IHttpClientFactory>();

    public static BattleNetService BattleNet = new BattleNetService(_httpClientFactory);

    public static GoogleNetService Google = new GoogleNetService(_httpClientFactory);

    public static HOTPNetService HOTP = new HOTPNetService(_httpClientFactory);

    public static MicrosoftNetService Microsoft = new MicrosoftNetService(_httpClientFactory);

}
