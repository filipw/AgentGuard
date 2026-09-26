using System.Net;
using System.Text;

namespace AgentGuard.Azure.Tests;

/// <summary>
/// An HTTP handler that answers each request with the given delegate, which gets the zero-based call
/// index and the request's cancellation token.
/// </summary>
internal sealed class LambdaHttpHandler(Func<int, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
{
    private int _calls;

    public int Calls => Volatile.Read(ref _calls);

    /// <summary>A handler that waits until the request is canceled, the way a service that stops answering behaves.</summary>
    public static LambdaHttpHandler Hanging() => new(async (_, ct) =>
    {
        await Task.Delay(Timeout.Infinite, ct);
        throw new InvalidOperationException("unreachable");
    });

    /// <summary>A handler whose every request fails in transport, the way an unreachable service does.</summary>
    public static LambdaHttpHandler Unreachable() =>
        new((_, _) => Task.FromException<HttpResponseMessage>(new HttpRequestException("No connection could be made.")));

    /// <summary>
    /// A handler that cancels <paramref name="caller"/> and then fails the request the way a connection
    /// torn down by that cancellation can: with an I/O error, which <see cref="HttpClient"/> passes on
    /// as it is rather than as a cancellation.
    /// </summary>
    public static LambdaHttpHandler CancelsThenFails(CancellationTokenSource caller) => new(async (_, _) =>
    {
        await caller.CancelAsync();
        throw new IOException("The connection was aborted.");
    });

    /// <summary>An OK response with a JSON body.</summary>
    public static HttpResponseMessage Json(string body) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(body, Encoding.UTF8, "application/json")
    };

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
        send(Interlocked.Increment(ref _calls) - 1, cancellationToken);
}
