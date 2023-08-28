// ReSharper disable once CheckNamespace
namespace BD.WTTS.Models;

public interface IGoogleNetService
{
    Task<HttpResponseMessage> TimeSync();
}
