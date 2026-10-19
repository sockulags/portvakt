package se.portvakt.sdk;

import com.nimbusds.jose.util.JSONObjectUtils;
import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import se.portvakt.sdk.internal.Http;

/**
 * Portvakt's discovery metadata, cached for {@code discoveryCacheTtl} and fetched once at a time
 * (concurrent callers share one request). When a refresh fails the last good metadata stays in
 * use (stale-if-error) and the next attempt waits 30 seconds; with nothing cached, a failure is
 * repeated without a request for {@code failureCacheTtl} (negative cache). The published issuer
 * must equal the configured one exactly. Thread-safe.
 */
public final class PortvaktDiscovery {
  private static final System.Logger LOG = System.getLogger(PortvaktDiscovery.class.getName());
  private static final Duration RETRY_AFTER_FAILURE = Duration.ofSeconds(30);
  private static final int MAX_BYTES = 256 * 1024;

  private record Current(ProviderMetadata metadata, Instant fetchedAt) {}

  private record Failure(RuntimeException error, Instant until) {}

  private final PortvaktConfig config;
  private final Http http;
  private Current current;
  private Instant retryAt = Instant.MIN;
  private Failure failure;
  private CompletableFuture<ProviderMetadata> pending;

  public PortvaktDiscovery(PortvaktConfig config) {
    this(config, new Http(config.httpClient(), config.httpTimeout()));
  }

  PortvaktDiscovery(PortvaktConfig config, Http http) {
    this.config = config;
    this.http = http;
  }

  /**
   * The metadata (cached).
   *
   * @throws PortvaktUnavailableException Portvakt is unreachable and nothing is cached
   * @throws PortvaktException {@code discovery_failed} for an unusable answer
   */
  public ProviderMetadata get() {
    Instant now = config.clock().instant();
    CompletableFuture<ProviderMetadata> shared;
    boolean owner = false;
    Current cached;
    synchronized (this) {
      cached = current;
      if (cached != null) {
        boolean fresh = now.isBefore(cached.fetchedAt.plus(config.discoveryCacheTtl()));
        if (fresh || now.isBefore(retryAt)) return cached.metadata;
      } else if (failure != null && now.isBefore(failure.until)) {
        throw failure.error;
      }
      if (pending == null) {
        pending = new CompletableFuture<>();
        owner = true;
      }
      shared = pending;
    }
    if (owner) {
      try {
        shared.complete(fetch());
      } catch (RuntimeException exception) {
        shared.completeExceptionally(exception);
      } finally {
        synchronized (this) {
          pending = null;
        }
      }
    }
    try {
      return shared.join();
    } catch (CompletionException completion) {
      RuntimeException error =
          completion.getCause() instanceof RuntimeException runtime
              ? runtime
              : new PortvaktUnavailableException("Portvakt discovery failed", completion.getCause());
      synchronized (this) {
        Instant failedAt = config.clock().instant();
        if (current != null) {
          retryAt = failedAt.plus(RETRY_AFTER_FAILURE);
          LOG.log(Level.WARNING, "Portvakt discovery refresh failed ({0}); using cached metadata", codeOf(error));
          return current.metadata;
        }
        failure = new Failure(error, failedAt.plus(config.failureCacheTtl()));
      }
      throw error;
    }
  }

  private ProviderMetadata fetch() {
    URI uri = URI.create(config.issuer() + "/.well-known/openid-configuration");
    Http.Response response;
    try {
      response = http.get(uri, MAX_BYTES);
    } catch (IOException exception) {
      LOG.log(Level.ERROR, "Portvakt discovery failed: {0}", exception.getClass().getSimpleName());
      throw new PortvaktUnavailableException("Portvakt discovery failed", exception);
    }
    if (response.status() >= 500) {
      LOG.log(Level.ERROR, "Portvakt discovery answered {0}", response.status());
      throw new PortvaktUnavailableException("Portvakt discovery answered " + response.status());
    }
    if (!response.ok()) {
      LOG.log(Level.ERROR, "Portvakt discovery answered {0}", response.status());
      throw new PortvaktException("discovery_failed", "Portvakt discovery failed", 502);
    }
    try {
      Map<String, Object> raw = JSONObjectUtils.parse(response.body());
      Object issuer = raw.get("issuer");
      if (!config.issuer().equals(issuer)) {
        throw new PortvaktException(
            "discovery_failed", "the discovered issuer is not the configured issuer", 502);
      }
      ProviderMetadata metadata =
          new ProviderMetadata(
              config.issuer(),
              endpoint(raw, "authorization_endpoint", true),
              endpoint(raw, "token_endpoint", true),
              endpoint(raw, "jwks_uri", true),
              endpoint(raw, "end_session_endpoint", false),
              withoutNulls(raw));
      synchronized (this) {
        current = new Current(metadata, config.clock().instant());
        retryAt = Instant.MIN;
        failure = null;
      }
      return metadata;
    } catch (java.text.ParseException | IllegalArgumentException exception) {
      LOG.log(Level.ERROR, "Portvakt discovery: unusable metadata");
      throw new PortvaktException("discovery_failed", "Portvakt discovery failed", 502, exception);
    }
  }

  private URI endpoint(Map<String, Object> raw, String name, boolean required) {
    Object value = raw.get(name);
    if (value == null && !required) return null;
    if (!(value instanceof String text)) throw new IllegalArgumentException(name);
    URI uri = URI.create(text);
    String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
    if (!scheme.equals("https") && !(scheme.equals("http") && config.allowInsecureRequests())) {
      throw new IllegalArgumentException(name);
    }
    return uri;
  }

  private static Map<String, Object> withoutNulls(Map<String, Object> raw) {
    Map<String, Object> copy = new HashMap<>();
    raw.forEach(
        (key, value) -> {
          if (value != null) copy.put(key, value);
        });
    return copy;
  }

  private static String codeOf(RuntimeException error) {
    return error instanceof PortvaktException portvakt ? portvakt.code() : error.getClass().getSimpleName();
  }
}
