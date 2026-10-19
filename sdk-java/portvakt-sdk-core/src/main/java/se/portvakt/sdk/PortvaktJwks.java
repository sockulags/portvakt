package se.portvakt.sdk;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.function.Supplier;
import se.portvakt.sdk.internal.Http;

/**
 * Portvakt's ES256 signing keys, with the same semantics as the TypeScript SDK:
 *
 * <ul>
 *   <li>keys are cached for {@code jwksCacheMaxAge} and then refetched;
 *   <li>an unknown {@code kid} triggers a refetch, at most once per {@code jwksCooldown} (so
 *       tokens with made-up kids cannot hammer Portvakt); within the cooldown it is refused;
 *   <li>a failed refetch keeps the last keys (stale-if-error) until {@code jwksCacheMaxAge +
 *       jwksStaleMaxAge} after their last successful fetch; past that, validation fails as
 *       unavailable, also within the cooldown;
 *   <li>without any keys, a failed fetch is repeated at most once per {@code failureCacheTtl}
 *       (negative cache).
 * </ul>
 *
 * Concurrent callers share one fetch (single flight). Thread-safe.
 */
public final class PortvaktJwks {
  private static final System.Logger LOG = System.getLogger(PortvaktJwks.class.getName());
  private static final int MAX_BYTES = 512 * 1024;
  private static final int MAX_KEYS = 100;

  /** The token names a key that is not (or no longer) in Portvakt's JWKS. */
  public static final class UnknownKeyException extends PortvaktException {
    private static final long serialVersionUID = 1L;

    UnknownKeyException() {
      super("unknown_key", "the token's signing key is unknown", 401);
    }
  }

  private record Cached(List<JWK> keys, Instant fetchedAt) {}

  private final PortvaktConfig config;
  private final Supplier<URI> jwksUri;
  private final Http http;
  private Cached cached;
  private Instant lastAttempt = Instant.MIN;
  private Instant lastFailure = Instant.MIN;
  private CompletableFuture<Cached> pending;

  /**
   * @param jwksUri where the keys are (usually from discovery); may throw {@link
   *     PortvaktUnavailableException}
   */
  public PortvaktJwks(PortvaktConfig config, Supplier<URI> jwksUri) {
    this(config, jwksUri, new Http(config.httpClient(), config.httpTimeout()));
  }

  PortvaktJwks(PortvaktConfig config, Supplier<URI> jwksUri, Http http) {
    this.config = config;
    this.jwksUri = jwksUri;
    this.http = http;
  }

  /**
   * The public ES256 key for {@code kid}.
   *
   * @throws UnknownKeyException the kid is unknown (after a refetch, when one was allowed)
   * @throws PortvaktUnavailableException the keys cannot be fetched, or are too old to trust
   */
  public ECKey keyFor(String kid) {
    if (kid == null || kid.isEmpty() || kid.length() > 255) throw new UnknownKeyException();
    Instant now = config.clock().instant();
    Cached keys;
    synchronized (this) {
      keys = cached;
      if (keys == null && now.isBefore(lastFailure.plus(config.failureCacheTtl()))) {
        throw new PortvaktUnavailableException("Portvakt's signing keys are unavailable");
      }
    }
    if (keys == null) {
      keys = refetch();
    } else if (!now.isBefore(keys.fetchedAt.plus(config.jwksCacheMaxAge())) && mayRefetch(now)) {
      keys = refetch();
    }
    ECKey key = find(keys.keys, kid);
    if (key == null && mayRefetch(config.clock().instant())) {
      keys = refetch();
      key = find(keys.keys, kid);
    }
    // Keys whose refetches kept failing are trusted only for a bounded time.
    Instant limit = keys.fetchedAt.plus(config.jwksCacheMaxAge()).plus(config.jwksStaleMaxAge());
    if (config.clock().instant().isAfter(limit)) {
      throw new PortvaktUnavailableException("Portvakt's signing keys are too old to trust");
    }
    if (key == null) throw new UnknownKeyException();
    return key;
  }

  private synchronized boolean mayRefetch(Instant now) {
    return !now.isBefore(lastAttempt.plus(config.jwksCooldown()));
  }

  /** Fetches the JWKS (shared by concurrent callers); on failure the cached keys stay. */
  private Cached refetch() {
    CompletableFuture<Cached> shared;
    boolean owner = false;
    synchronized (this) {
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
      Throwable cause = completion.getCause();
      synchronized (this) {
        lastFailure = config.clock().instant();
        if (cached != null) {
          LOG.log(Level.WARNING, "Portvakt JWKS refetch failed ({0}); using cache", describe(cause));
          return cached;
        }
      }
      LOG.log(Level.ERROR, "Portvakt JWKS unavailable ({0})", describe(cause));
      throw new PortvaktUnavailableException("Portvakt's signing keys are unavailable", cause);
    }
  }

  private Cached fetch() {
    synchronized (this) {
      lastAttempt = config.clock().instant();
    }
    URI uri = jwksUri.get();
    String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
    if (!scheme.equals("https") && !(scheme.equals("http") && config.allowInsecureRequests())) {
      throw new PortvaktException("jwks_failed", "jwks_uri must be https", 502);
    }
    Http.Response response;
    try {
      response = http.get(uri, MAX_BYTES);
    } catch (IOException exception) {
      throw new PortvaktUnavailableException("jwks_uri unreachable", exception);
    }
    if (!response.ok()) {
      throw new PortvaktUnavailableException("jwks_uri answered " + response.status());
    }
    List<JWK> keys;
    try {
      keys = JWKSet.parse(response.body()).getKeys();
    } catch (java.text.ParseException exception) {
      throw new PortvaktException("jwks_failed", "jwks_uri answered an invalid JWKS", 502, exception);
    }
    if (keys.size() > MAX_KEYS) {
      throw new PortvaktException("jwks_failed", "jwks_uri answered too many keys", 502);
    }
    Cached fetched = new Cached(List.copyOf(keys), config.clock().instant());
    synchronized (this) {
      cached = fetched;
    }
    return fetched;
  }

  /** A public ES256 signing key with this kid. */
  private static ECKey find(List<JWK> keys, String kid) {
    for (JWK key : keys) {
      if (!kid.equals(key.getKeyID())) continue;
      if (!(key instanceof ECKey ec) || !Curve.P_256.equals(ec.getCurve())) continue;
      if (key.getAlgorithm() != null && !JWSAlgorithm.ES256.equals(key.getAlgorithm())) continue;
      if (key.getKeyUse() != null && !KeyUse.SIGNATURE.equals(key.getKeyUse())) continue;
      if (key.isPrivate()) continue;
      return ec;
    }
    return null;
  }

  private static String describe(Throwable cause) {
    if (cause instanceof PortvaktException portvakt) return portvakt.code();
    return cause == null ? "unknown" : cause.getClass().getSimpleName();
  }
}
