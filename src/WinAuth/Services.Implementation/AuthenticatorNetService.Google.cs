// ReSharper disable once CheckNamespace
namespace BD.WTTS.Models;

using System.Net.Http.Client;

public sealed partial class GoogleNetService : IGoogleNetService
{
    public GoogleNetService()
    {
    }

    /// <summary>
    /// URL used to sync time
    /// </summary>
    const string TIME_SYNC_URL = "http://www.google.com";

    public async Task<HttpResponseMessage> TimeSync()
    {
        using var requestMessage = new HttpRequestMessage(HttpMethod.Get, TIME_SYNC_URL)
        {
            Content = new StringContent(string.Empty, Encoding.UTF8, "text/html"),
        };
        using var client = new HttpClient();
        client.Timeout = new TimeSpan(0, 0, 5);
        return await client.SendAsync(requestMessage);
    }
}
