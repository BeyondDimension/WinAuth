// ReSharper disable once CheckNamespace
namespace BD.WTTS.Models;

using System.Net.Http.Client;
using Microsoft.Extensions.Options;
using System.Net.Http;

/// <summary>
/// Extensions methods for <see cref="IHttpClientFactory"/>.
/// </summary>
public static class HttpClientFactoryExtensions
{
    /// <summary>
    /// Creates a new <see cref="HttpClient"/> using the default configuration.
    /// </summary>
    /// <param name="factory">The <see cref="IHttpClientFactory"/>.</param>
    /// <returns>An <see cref="HttpClient"/> configured using the default configuration.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static HttpClient CreateClient(this IHttpClientFactory factory)
    {
        return factory.CreateClient(Options.DefaultName);
    }
}
