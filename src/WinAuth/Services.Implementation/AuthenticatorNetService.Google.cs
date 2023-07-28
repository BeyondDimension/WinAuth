// ReSharper disable once CheckNamespace
namespace BD.WTTS.Models;

using System.Net.Http.Client;

public sealed partial class GoogleNetService : IGoogleNetService
{
    private readonly IHttpClientFactory _httpClientFactory;

    public GoogleNetService(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    /// <summary>
    /// URL used to sync time
    /// </summary>
    const string TIME_SYNC_URL = "http://www.google.com";

    public HttpResponseMessage TimeSync()
    {
        using var requestMessage = new HttpRequestMessage(HttpMethod.Get, TIME_SYNC_URL)
        {
            Content = new StringContent(string.Empty, Encoding.UTF8, "text/html"),
        };
        using var client = _httpClientFactory.CreateClient();
        client.Timeout = new TimeSpan(0, 0, 5);
        return client.Send(requestMessage);
    }
}
