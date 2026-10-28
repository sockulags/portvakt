package se.portvakt.sdk;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import se.portvakt.sdk.internal.Http;

/**
 * Service-to-service tokens: the {@code client_credentials} grant with the resource indicator
 * {@code urn:portvakt:app:{audience}} (RFC 8707). Tokens are cached until shortly before they
 * expire (10% of the lifetime, at least 30 s, at most half the lifetime) and fetched once at a
 * time per audience. A network error, a timeout or a 5xx answer is {@link
 * PortvaktUnavailableException}; a 429 or the OAuth error {@code temporarily_unavailable} is
 * {@link PortvaktRetryLaterException} (with Portvakt's {@code Retry-After}); any other refusal is
 * a {@link PortvaktException} with Portvakt's OAuth error code (HTTP 502). The target must be
 * enabled in the same tenant. Thread-safe.
 */
public final class ClientCredentialsTokenProvider {
  private static final System.Logger LOG =
      System.getLogger(ClientCredentialsTokenProvider.class.getName());
  private static final int MAX_BYTES = 64 * 1024;
  private static final Pattern OAUTH_ERROR = Pattern.compile("^[a-z_]{1,64}$");

  /** Portvakt's resource indicator (RFC 8707) of an application. */
  public static String resourceIndicatorFor(String clientId) {
    return "urn:portvakt:app:" + clientId;
  }

  private final PortvaktConfig config;
  private final PortvaktDiscovery discovery;
  private final Http http;
  private final Map<String, Source> sources = new ConcurrentHashMap<>();

  public ClientCredentialsTokenProvider(PortvaktConfig config, PortvaktDiscovery discovery) {
    this(config, discovery, new Http(config.httpClient(), config.httpTimeout()));
  }

  ClientCredentialsTokenProvider(PortvaktConfig config, PortvaktDiscovery discovery, Http http) {
    if (config.clientAuth() == null) {
      throw new PortvaktConfigException(List.of("clientAuth: required for client_credentials"));
    }
    this.config = config;
    this.discovery = discovery;
    this.http = http;
  }

  /** The (shared, cached) token source for one target application. */
  public ServiceTokenSource forAudience(String audience) {
    if (audience == null || audience.isEmpty() || audience.length() > 255) {
      throw new PortvaktConfigException(List.of("audience: required, 1 to 255 characters"));
    }
    return sources.computeIfAbsent(audience, Source::new);
  }

  /** A valid token for {@code audience} (see {@link ServiceTokenSource#getToken()}). */
  public String getToken(String audience) {
    return forAudience(audience).getToken();
  }

  /** Fetches early: 10% of the lifetime, at least 30 seconds, at most half the lifetime. */
  static long refreshMarginSeconds(long lifetimeSeconds) {
    return (long) Math.min(Math.max(30, lifetimeSeconds * 0.1), lifetimeSeconds / 2.0);
  }

  private final class Source implements ServiceTokenSource {
    private record Cached(String token, Instant refreshAt) {}

    private final String audience;
    private Cached cached;
    private CompletableFuture<String> pending;

    Source(String audience) {
      this.audience = audience;
    }

    @Override
    public String audience() {
      return audience;
    }

    @Override
    public String getToken() {
      CompletableFuture<String> shared;
      boolean owner = false;
      synchronized (this) {
        if (cached != null && config.clock().instant().isBefore(cached.refreshAt)) return cached.token;
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
        if (completion.getCause() instanceof RuntimeException runtime) throw runtime;
        throw new PortvaktUnavailableException("Portvakt is unavailable", completion.getCause());
      }
    }

    @Override
    public synchronized void clear() {
      cached = null;
    }

    private String fetch() {
      ProviderMetadata metadata = discovery.get();
      Map<String, String> form = new LinkedHashMap<>();
      form.put("grant_type", "client_credentials");
      form.put("resource", resourceIndicatorFor(audience));
      Map<String, String> headers = new LinkedHashMap<>();
      authenticate(metadata, form, headers);
      Http.Response response;
      try {
        response = http.postForm(metadata.tokenEndpoint(), form, headers, MAX_BYTES);
      } catch (IOException exception) {
        LOG.log(Level.WARNING, "client_credentials grant failed for {0}: {1}", audience, exception.getClass().getSimpleName());
        throw new PortvaktUnavailableException("Portvakt is unavailable", exception);
      }
      if (response.status() >= 500) {
        LOG.log(Level.WARNING, "client_credentials grant for {0}: Portvakt answered {1}", audience, response.status());
        throw new PortvaktUnavailableException("Portvakt answered " + response.status());
      }
      Map<String, Object> body;
      try {
        body = JSONObjectUtils.parse(response.body());
      } catch (java.text.ParseException exception) {
        body = Map.of();
      }
      if (!response.ok()) {
        Object error = body.get("error");
        String code = error instanceof String text && OAUTH_ERROR.matcher(text).matches() ? text : "token_request_failed";
        if (response.status() == 429 || code.equals("temporarily_unavailable")) {
          // Portvakt asked to be retried later (a rate limit): transient, not a refusal.
          LOG.log(Level.WARNING, "client_credentials grant for {0}: Portvakt asked to retry later", audience);
          throw new PortvaktRetryLaterException(
              PortvaktRetryLaterException.parseRetryAfter(response.retryAfter(), config.clock().instant()));
        }
        LOG.log(Level.WARNING, "client_credentials grant for {0} refused: {1}", audience, code);
        throw new PortvaktException(code, "Portvakt refused the client_credentials grant", 502);
      }
      Object token = body.get("access_token");
      if (!(token instanceof String accessToken) || accessToken.isEmpty()) {
        throw new PortvaktException("token_request_failed", "Portvakt answered without an access token", 502);
      }
      long lifetime = body.get("expires_in") instanceof Number number && number.longValue() > 0 ? number.longValue() : 60;
      Instant refreshAt =
          config.clock().instant().plusSeconds(lifetime - refreshMarginSeconds(lifetime));
      synchronized (this) {
        cached = new Cached(accessToken, refreshAt);
      }
      return accessToken;
    }
  }

  private void authenticate(ProviderMetadata metadata, Map<String, String> form, Map<String, String> headers) {
    switch (config.clientAuth()) {
      case ClientAuth.ClientSecret secret when secret.method().equals("client_secret_post") -> {
        form.put("client_id", config.clientId());
        form.put("client_secret", secret.clientSecret());
      }
      case ClientAuth.ClientSecret secret -> {
        // RFC 6749 section 2.3.1: both parts form-encoded before the Basic encoding.
        String pair =
            URLEncoder.encode(config.clientId(), StandardCharsets.UTF_8)
                + ":"
                + URLEncoder.encode(secret.clientSecret(), StandardCharsets.UTF_8);
        headers.put(
            "Authorization",
            "Basic " + Base64.getEncoder().encodeToString(pair.getBytes(StandardCharsets.UTF_8)));
      }
      case ClientAuth.PrivateKeyJwt key -> {
        form.put("client_id", config.clientId());
        form.put("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        form.put("client_assertion", clientAssertion(key.privateJwk(), metadata));
      }
    }
  }

  /** A client assertion (RFC 7523): signed by the application's key, valid for 60 seconds. */
  String clientAssertion(JWK jwk, ProviderMetadata metadata) {
    Instant now = config.clock().instant();
    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .issuer(config.clientId())
            .subject(config.clientId())
            .audience(metadata.issuer())
            .jwtID(UUID.randomUUID().toString())
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plus(Duration.ofSeconds(60))))
            .build();
    try {
      JWSAlgorithm algorithm;
      JWSSigner signer;
      if (jwk instanceof ECKey ec) {
        algorithm = jwk.getAlgorithm() == null ? JWSAlgorithm.ES256 : JWSAlgorithm.parse(jwk.getAlgorithm().getName());
        signer = new ECDSASigner(ec);
      } else if (jwk instanceof RSAKey rsa) {
        algorithm = jwk.getAlgorithm() == null ? JWSAlgorithm.RS256 : JWSAlgorithm.parse(jwk.getAlgorithm().getName());
        signer = new RSASSASigner(rsa);
      } else {
        throw new PortvaktConfigException(List.of("clientAuth.privateJwk: must be an EC or RSA key"));
      }
      SignedJWT assertion =
          new SignedJWT(
              new JWSHeader.Builder(algorithm).keyID(jwk.getKeyID()).type(JOSEObjectType.JWT).build(),
              claims);
      assertion.sign(signer);
      return assertion.serialize();
    } catch (JOSEException exception) {
      throw new PortvaktConfigException(List.of("clientAuth.privateJwk: cannot sign with this key"));
    }
  }
}
