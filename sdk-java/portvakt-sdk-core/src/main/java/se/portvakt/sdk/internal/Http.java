package se.portvakt.sdk.internal;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Requests to Portvakt: one deadline for the whole request (connect, headers and body), no
 * redirects, bounded response bodies (read while they arrive, never buffered beyond the limit).
 * Internal API.
 */
public final class Http {
  /** A response: status and body (at most the limit). */
  public record Response(int status, String body) {
    public boolean ok() {
      return status >= 200 && status < 300;
    }
  }

  /** The body was larger than allowed. */
  public static final class TooLarge extends IOException {
    private static final long serialVersionUID = 1L;

    TooLarge() {
      super("response too large");
    }
  }

  private final HttpClient client;
  private final Duration timeout;

  public Http(HttpClient client, Duration timeout) {
    this.client =
        client != null
            ? client
            : HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(timeout)
                .build();
    this.timeout = timeout;
  }

  /** GET accepting JSON. */
  public Response get(URI uri, int maxBytes) throws IOException {
    HttpRequest request =
        HttpRequest.newBuilder(uri).timeout(timeout).header("Accept", "application/json").GET().build();
    return send(request, maxBytes);
  }

  /** POST of a form (application/x-www-form-urlencoded) with extra headers. */
  public Response postForm(URI uri, Map<String, String> form, Map<String, String> headers, int maxBytes)
      throws IOException {
    HttpRequest.Builder builder =
        HttpRequest.newBuilder(uri)
            .timeout(timeout)
            .header("Accept", "application/json")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(formEncode(form)));
    headers.forEach(builder::header);
    return send(builder.build(), maxBytes);
  }

  /** {@code application/x-www-form-urlencoded} encoding. */
  public static String formEncode(Map<String, String> form) {
    StringJoiner joiner = new StringJoiner("&");
    form.forEach(
        (key, value) ->
            joiner.add(
                URLEncoder.encode(key, StandardCharsets.UTF_8)
                    + "="
                    + URLEncoder.encode(value, StandardCharsets.UTF_8)));
    return joiner.toString();
  }

  private Response send(HttpRequest request, int maxBytes) throws IOException {
    CompletableFuture<HttpResponse<byte[]>> pending =
        client.sendAsync(request, info -> new LimitedBody(maxBytes));
    try {
      HttpResponse<byte[]> response = pending.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
      return new Response(response.statusCode(), new String(response.body(), StandardCharsets.UTF_8));
    } catch (TimeoutException deadline) {
      pending.cancel(true);
      throw new HttpTimeoutException("request to Portvakt timed out");
    } catch (InterruptedException interrupted) {
      pending.cancel(true);
      Thread.currentThread().interrupt();
      throw new IOException("interrupted", interrupted);
    } catch (ExecutionException failed) {
      Throwable cause = failed.getCause();
      if (cause instanceof IOException io) throw io;
      throw new IOException(cause == null ? "request failed" : cause.getClass().getSimpleName(), cause);
    }
  }

  /** Collects the body, failing as soon as it exceeds the limit. */
  private static final class LimitedBody implements HttpResponse.BodySubscriber<byte[]> {
    private final int maxBytes;
    private final CompletableFuture<byte[]> result = new CompletableFuture<>();
    private final List<ByteBuffer> parts = new ArrayList<>();
    private Flow.Subscription subscription;
    private int size;

    LimitedBody(int maxBytes) {
      this.maxBytes = maxBytes;
    }

    @Override
    public CompletionStage<byte[]> getBody() {
      return result;
    }

    @Override
    public void onSubscribe(Flow.Subscription value) {
      subscription = value;
      value.request(Long.MAX_VALUE);
    }

    @Override
    public void onNext(List<ByteBuffer> items) {
      for (ByteBuffer item : items) {
        size += item.remaining();
        if (size > maxBytes) {
          subscription.cancel();
          result.completeExceptionally(new TooLarge());
          return;
        }
        parts.add(item);
      }
    }

    @Override
    public void onError(Throwable error) {
      result.completeExceptionally(error);
    }

    @Override
    public void onComplete() {
      if (result.isDone()) return;
      byte[] bytes = new byte[size];
      int offset = 0;
      for (ByteBuffer part : parts) {
        int length = part.remaining();
        part.get(bytes, offset, length);
        offset += length;
      }
      result.complete(bytes);
    }
  }
}
