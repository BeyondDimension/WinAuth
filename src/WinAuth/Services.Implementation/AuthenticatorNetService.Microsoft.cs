// ReSharper disable once CheckNamespace
namespace BD.WTTS.Models;

using System.Net.Http.Client;

public sealed partial class MicrosoftNetService : IMicrosoftNetService
{
    private readonly IHttpClientFactory _httpClientFactory;

    public MicrosoftNetService(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }
}
