package se.portvakt.spring.login;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

/**
 * One deadline for a whole request to Portvakt's token endpoint: connect, headers and the body,
 * read completely (bounded) within the deadline, so a server that trickles its answer cannot hold
 * a request (and the session's refresh lock) longer than the HTTP timeout.
 */
public class DeadlineInterceptor implements ClientHttpRequestInterceptor {
  private static final int MAX_BYTES = 256 * 1024;
  private static final ExecutorService EXECUTOR = Executors.newVirtualThreadPerTaskExecutor();

  private final Duration deadline;

  public DeadlineInterceptor(Duration deadline) {
    this.deadline = deadline;
  }

  @Override
  public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
      throws IOException {
    Future<Buffered> pending =
        EXECUTOR.submit(
            () -> {
              try (ClientHttpResponse response = execution.execute(request, body)) {
                byte[] bytes = response.getBody().readNBytes(MAX_BYTES + 1);
                if (bytes.length > MAX_BYTES) throw new IOException("response too large");
                HttpHeaders headers = new HttpHeaders();
                headers.putAll(response.getHeaders());
                return new Buffered(response.getStatusCode(), response.getStatusText(), headers, bytes);
              }
            });
    try {
      return pending.get(deadline.toMillis(), TimeUnit.MILLISECONDS);
    } catch (TimeoutException timedOut) {
      pending.cancel(true);
      throw new SocketTimeoutException("request to Portvakt timed out");
    } catch (InterruptedException interrupted) {
      pending.cancel(true);
      Thread.currentThread().interrupt();
      throw new IOException("interrupted", interrupted);
    } catch (ExecutionException failed) {
      if (failed.getCause() instanceof IOException io) throw io;
      if (failed.getCause() instanceof RuntimeException runtime) throw runtime;
      throw new IOException("request failed", failed.getCause());
    }
  }

  private record Buffered(HttpStatusCode status, String text, HttpHeaders headers, byte[] bytes)
      implements ClientHttpResponse {
    @Override
    public HttpStatusCode getStatusCode() {
      return status;
    }

    @Override
    public String getStatusText() {
      return text;
    }

    @Override
    public HttpHeaders getHeaders() {
      return headers;
    }

    @Override
    public InputStream getBody() {
      return new ByteArrayInputStream(bytes);
    }

    @Override
    public void close() {}
  }
}
