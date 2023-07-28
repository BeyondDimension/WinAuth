// ReSharper disable once CheckNamespace
namespace BD.WTTS.Models;

public interface IBattleNetService
{
    Task<HttpResponseMessage> GEOIP();

    Task<HttpResponseMessage> EnRoll(string region, byte[] encrypted);

    HttpResponseMessage Sync(string Region);

    Task<HttpResponseMessage> ReStore(string serial, byte[] serialBytes);

    Task<HttpResponseMessage> ReStoreValidate(string serial, byte[] postbytes);
}
