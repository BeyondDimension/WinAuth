// ReSharper disable once CheckNamespace
namespace BD.WTTS.Models;

using System.Net.Http.Client;

public sealed class BattleNetService : IBattleNetService
{
    private readonly IHttpClientFactory _httpClientFactory;

    public BattleNetService(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    /// <summary>
    /// URLs for all mobile services
    /// </summary>
    const string REGION_US = "US";
    const string REGION_EU = "EU";
    const string REGION_KR = "KR";
    const string REGION_CN = "CN";
    public static Dictionary<string, string> MOBILE_URLS = new()
    {
        { REGION_US, "http://mobile-service.blizzard.com" },
        { REGION_EU, "http://mobile-service.blizzard.com" },
        { REGION_KR, "http://mobile-service.blizzard.com" },
        { REGION_CN, "http://mobile-service.battlenet.com.cn" },
    };

    const string ENROLL_PATH = "/enrollment/enroll2.htm";
    const string SYNC_PATH = "/enrollment/time.htm";
    const string RESTORE_PATH = "/enrollment/initiatePaperRestore.htm";
    const string RESTOREVALIDATE_PATH = "/enrollment/validatePaperRestore.htm";

    /// <summary>
    /// URL for GEO IP lookup to determine region
    /// </summary>
    static readonly string GEOIPURL = "http://geoiplookup.wikimedia.org";

    /// <summary>
    /// Get the base mobil url based on the region
    /// </summary>
    /// <param name="region">two letter region code, i.e US or CN</param>
    /// <returns>string of Url for region</returns>
    private static string GetMobileUrl(string region)
    {
        var upperregion = region.ToUpper();
        if (upperregion.Length > 2)
        {
            upperregion = upperregion[..2];
        }
        if (MOBILE_URLS.ContainsKey(upperregion) == true)
        {
            return MOBILE_URLS[upperregion];
        }
        else
        {
            return MOBILE_URLS[REGION_US];
        }
    }

    public async Task<HttpResponseMessage> GEOIP()
    {
        using var requestMessage = new HttpRequestMessage(HttpMethod.Get, GEOIPURL)
        {
            Content = new StringContent(string.Empty, Encoding.UTF8, "application/json"),
        };
        using var httpClient = _httpClientFactory.CreateClient();
        httpClient.Timeout = TimeSpan.FromSeconds(10);
        return await httpClient.SendAsync(requestMessage);
    }

    public async Task<HttpResponseMessage> EnRoll(string region, byte[] encrypted)
    {
        using var requestMessage = new HttpRequestMessage(HttpMethod.Post, GetMobileUrl(region) + ENROLL_PATH)
        {
            Content = new StringContent(Encoding.UTF8.GetString(encrypted, 0, encrypted.Length), Encoding.UTF8, "application/octet-stream"),
        };
        using var httpClient = _httpClientFactory.CreateClient();
        requestMessage.Content.Headers.ContentLength = encrypted.Length;

        return await httpClient.SendAsync(requestMessage);
    }

    public HttpResponseMessage Sync(string Region)
    {
        using var requestMessage = new HttpRequestMessage(HttpMethod.Get, GetMobileUrl(Region) + SYNC_PATH);
        using var httpClient = _httpClientFactory.CreateClient();
        httpClient.Timeout = TimeSpan.FromSeconds(5);

        return httpClient.Send(requestMessage);
    }

    public async Task<HttpResponseMessage> ReStore(string serial, byte[] serialBytes)
    {
        using var requestMessage = new HttpRequestMessage(HttpMethod.Post, GetMobileUrl(serial) + RESTORE_PATH)
        {
            Content = new StringContent(Encoding.UTF8.GetString(serialBytes, 0, serialBytes.Length), Encoding.UTF8, "application/octet-stream"),
        };
        requestMessage.Content.Headers.ContentLength = serialBytes.Length;
        using var httpClient = _httpClientFactory.CreateClient();
        return await httpClient.SendAsync(requestMessage);
    }

    public async Task<HttpResponseMessage> ReStoreValidate(string serial, byte[] postbytes)
    {
        using var requestMessage = new HttpRequestMessage(HttpMethod.Post, GetMobileUrl(serial) + RESTOREVALIDATE_PATH)
        {
            Content = new StringContent(Encoding.UTF8.GetString(postbytes, 0, postbytes.Length), Encoding.UTF8, "application/octet-stream"),
        };
        requestMessage.Content.Headers.ContentLength = postbytes.Length;
        using var httpClient = _httpClientFactory.CreateClient();
        return await httpClient.SendAsync(requestMessage);
    }
}
