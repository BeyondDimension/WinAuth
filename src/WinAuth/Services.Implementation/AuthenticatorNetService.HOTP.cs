// ReSharper disable once CheckNamespace
using System.Net.Http.Client;

namespace BD.WTTS.Models;

public sealed partial class HOTPNetService : IHOTPNetService
{
    private readonly IHttpClientFactory _httpClientFactory;

    public HOTPNetService(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }
}
