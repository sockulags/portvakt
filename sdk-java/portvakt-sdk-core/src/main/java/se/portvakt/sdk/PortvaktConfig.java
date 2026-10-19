package se.portvakt.sdk;

import com.nimbusds.jose.jwk.JWK;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * The validated SDK configuration. Build it with {@link #builder()}; {@link Builder#build()}
 * throws {@link PortvaktConfigException} listing every problem (never a secret value).
 */
public final class PortvaktConfig {
  private static final Pattern SCOPE = Pattern.compile("^[\\x21\\x23-\\x5B\\x5D-\\x7E]+$");

  private final String issuer;
  private final String clientId;
  private final ClientAuth clientAuth;
  private final List<String> scopes;
  private final Duration clockSkew;
  private final Duration httpTimeout;
  private final Duration discoveryCacheTtl;
  private final Duration failureCacheTtl;
  private final Duration jwksCacheMaxAge;
  private final Duration jwksCooldown;
  private final Duration jwksStaleMaxAge;
  private final AcrRanking acrRanking;
  private final boolean allowInsecureRequests;
  private final Clock clock;
  private final HttpClient httpClient;

  private PortvaktConfig(Builder builder) {
    this.issuer = builder.issuer;
    this.clientId = builder.clientId;
    this.clientAuth = builder.clientAuth;
    this.scopes = List.copyOf(builder.scopes);
    this.clockSkew = builder.clockSkew;
    this.httpTimeout = builder.httpTimeout;
    this.discoveryCacheTtl = builder.discoveryCacheTtl;
    this.failureCacheTtl = builder.failureCacheTtl;
    this.jwksCacheMaxAge = builder.jwksCacheMaxAge;
    this.jwksCooldown = builder.jwksCooldown;
    this.jwksStaleMaxAge = builder.jwksStaleMaxAge;
    this.acrRanking = builder.acrRanking;
    this.allowInsecureRequests = builder.allowInsecureRequests;
    this.clock = builder.clock;
    this.httpClient = builder.httpClient;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** The tenant issuer {@code {PUBLIC_URL}/t/{tenant}}, exactly; tokens must carry this {@code iss}. */
  public String issuer() {
    return issuer;
  }

  public String clientId() {
    return clientId;
  }

  /** The token endpoint authentication, or {@code null} for a resource server only. */
  public ClientAuth clientAuth() {
    return clientAuth;
  }

  public List<String> scopes() {
    return scopes;
  }

  public Duration clockSkew() {
    return clockSkew;
  }

  public Duration httpTimeout() {
    return httpTimeout;
  }

  public Duration discoveryCacheTtl() {
    return discoveryCacheTtl;
  }

  public Duration failureCacheTtl() {
    return failureCacheTtl;
  }

  public Duration jwksCacheMaxAge() {
    return jwksCacheMaxAge;
  }

  public Duration jwksCooldown() {
    return jwksCooldown;
  }

  public Duration jwksStaleMaxAge() {
    return jwksStaleMaxAge;
  }

  public AcrRanking acrRanking() {
    return acrRanking;
  }

  public boolean allowInsecureRequests() {
    return allowInsecureRequests;
  }

  public Clock clock() {
    return clock;
  }

  /** The HTTP client for every request to Portvakt, or {@code null} for the SDK's own. */
  public HttpClient httpClient() {
    return httpClient;
  }

  @Override
  public String toString() {
    return "PortvaktConfig[issuer=" + issuer + ", clientId=" + clientId + ", clientAuth=" + clientAuth + "]";
  }

  /** Builder with Portvakt's defaults (the same as the TypeScript SDK's). */
  public static final class Builder {
    private String issuer;
    private String clientId;
    private ClientAuth clientAuth;
    private List<String> scopes = List.of("openid", "profile", "email");
    private Duration clockSkew = Duration.ofSeconds(30);
    private Duration httpTimeout = Duration.ofSeconds(10);
    private Duration discoveryCacheTtl = Duration.ofHours(1);
    private Duration failureCacheTtl = Duration.ofSeconds(5);
    private Duration jwksCacheMaxAge = Duration.ofMinutes(5);
    private Duration jwksCooldown = Duration.ofSeconds(30);
    private Duration jwksStaleMaxAge = Duration.ofDays(1);
    private AcrRanking acrRanking = AcrRanking.DEFAULT;
    private boolean allowInsecureRequests;
    private Clock clock = Clock.systemUTC();
    private HttpClient httpClient;

    private Builder() {}

    /** Required: the tenant's issuer, exactly as Portvakt publishes it (no trailing slash). */
    public Builder issuer(String issuer) {
      this.issuer = issuer;
      return this;
    }

    /** Required: the application's client_id (also the default access token audience). */
    public Builder clientId(String clientId) {
      this.clientId = clientId;
      return this;
    }

    /** Required for logins and client_credentials; not for a resource server only. */
    public Builder clientAuth(ClientAuth clientAuth) {
      this.clientAuth = clientAuth;
      return this;
    }

    /** Default {@code openid profile email}; must include {@code openid}. */
    public Builder scopes(List<String> scopes) {
      this.scopes = scopes == null ? null : List.copyOf(scopes);
      return this;
    }

    /** Tolerance for {@code exp}, {@code nbf}, {@code iat}. Default 30 s, at most 300 s. */
    public Builder clockSkew(Duration clockSkew) {
      this.clockSkew = clockSkew;
      return this;
    }

    /** Timeout of every request to Portvakt. Default 10 s (1 s to 120 s). */
    public Builder httpTimeout(Duration httpTimeout) {
      this.httpTimeout = httpTimeout;
      return this;
    }

    /** Discovery metadata is fetched again after this. Default 1 h (stale kept on failure). */
    public Builder discoveryCacheTtl(Duration discoveryCacheTtl) {
      this.discoveryCacheTtl = discoveryCacheTtl;
      return this;
    }

    /** With nothing cached, a failed discovery or JWKS fetch is retried after this. Default 5 s. */
    public Builder failureCacheTtl(Duration failureCacheTtl) {
      this.failureCacheTtl = failureCacheTtl;
      return this;
    }

    /** Keys are refetched after this. Default 10 min. */
    public Builder jwksCacheMaxAge(Duration jwksCacheMaxAge) {
      this.jwksCacheMaxAge = jwksCacheMaxAge;
      return this;
    }

    /** At most one JWKS fetch per this; an unknown kid within it is refused. Default 30 s. */
    public Builder jwksCooldown(Duration jwksCooldown) {
      this.jwksCooldown = jwksCooldown;
      return this;
    }

    /**
     * While refetches fail, keys stay in use until the cache max age plus this after their last
     * successful fetch; then validation fails as unavailable. Default 1 day.
     */
    public Builder jwksStaleMaxAge(Duration jwksStaleMaxAge) {
      this.jwksStaleMaxAge = jwksStaleMaxAge;
      return this;
    }

    /** Must match Portvakt's {@code ACR_RANKING}. Default {@link AcrRanking#DEFAULT}. */
    public Builder acrRanking(AcrRanking acrRanking) {
      this.acrRanking = acrRanking;
      return this;
    }

    /** Allows an {@code http:} issuer (local development only). Default false. */
    public Builder allowInsecureRequests(boolean allowInsecureRequests) {
      this.allowInsecureRequests = allowInsecureRequests;
      return this;
    }

    /** The clock for token times and caches (tests). Default the system clock. */
    public Builder clock(Clock clock) {
      this.clock = clock;
      return this;
    }

    /** An HTTP client for every request to Portvakt (proxies). Redirects must not be followed. */
    public Builder httpClient(HttpClient httpClient) {
      this.httpClient = httpClient;
      return this;
    }

    /** Validates the configuration. */
    public PortvaktConfig build() {
      List<String> issues = new ArrayList<>();
      validateIssuer(issues);
      if (clientId == null || clientId.isEmpty() || clientId.length() > 255) {
        issues.add("clientId: required, 1 to 255 characters");
      }
      validateClientAuth(issues);
      if (scopes == null || scopes.isEmpty() || scopes.size() > 50) {
        issues.add("scopes: 1 to 50 scopes");
      } else {
        if (!scopes.contains("openid")) issues.add("scopes: must include openid");
        for (String scope : scopes) {
          if (scope == null || !SCOPE.matcher(scope).matches()) {
            issues.add("scopes: invalid scope");
            break;
          }
        }
      }
      range(issues, "clockSkew", clockSkew, Duration.ZERO, Duration.ofSeconds(300));
      range(issues, "httpTimeout", httpTimeout, Duration.ofSeconds(1), Duration.ofSeconds(120));
      range(issues, "discoveryCacheTtl", discoveryCacheTtl, Duration.ZERO, Duration.ofDays(1));
      range(issues, "failureCacheTtl", failureCacheTtl, Duration.ZERO, Duration.ofSeconds(300));
      range(issues, "jwksCacheMaxAge", jwksCacheMaxAge, Duration.ZERO, Duration.ofDays(1));
      range(issues, "jwksCooldown", jwksCooldown, Duration.ZERO, Duration.ofHours(1));
      range(issues, "jwksStaleMaxAge", jwksStaleMaxAge, Duration.ZERO, Duration.ofDays(7));
      if (acrRanking == null || acrRanking.levels().size() > 50) {
        issues.add("acrRanking: at most 50 levels");
      } else if (acrRanking.levels().stream()
          .anyMatch(level -> level == null || level.isEmpty() || level.length() > 255)) {
        issues.add("acrRanking: levels must be 1 to 255 characters");
      }
      if (clock == null) issues.add("clock: required");
      if (!issues.isEmpty()) throw new PortvaktConfigException(issues);
      return new PortvaktConfig(this);
    }

    private void validateIssuer(List<String> issues) {
      if (issuer == null || issuer.isEmpty()) {
        issues.add("issuer: required");
        return;
      }
      URI uri;
      try {
        uri = new URI(issuer);
      } catch (URISyntaxException exception) {
        issues.add("issuer: must be an absolute URL");
        return;
      }
      if (!uri.isAbsolute() || uri.getHost() == null) {
        issues.add("issuer: must be an absolute URL");
        return;
      }
      String scheme = uri.getScheme().toLowerCase(java.util.Locale.ROOT);
      if (!scheme.equals("https") && !(scheme.equals("http") && allowInsecureRequests)) {
        issues.add(
            "issuer: must be https (http only with allowInsecureRequests, for local development)");
      }
      if (uri.getRawFragment() != null || uri.getRawUserInfo() != null) {
        issues.add("issuer: must not carry a fragment or credentials");
      }
      if (issuer.endsWith("/") || uri.getRawQuery() != null) {
        issues.add("issuer: must be the issuer exactly, without a trailing slash or query");
      }
    }

    private void validateClientAuth(List<String> issues) {
      if (clientAuth == null) return;
      switch (clientAuth) {
        case ClientAuth.ClientSecret secret -> {
          String value = secret.clientSecret();
          if (value == null || value.length() < 16) {
            issues.add("clientAuth.clientSecret: at least 16 characters");
          } else if (value.length() > 4096) {
            issues.add("clientAuth.clientSecret: at most 4096 characters");
          }
          if (!secret.method().equals("client_secret_basic")
              && !secret.method().equals("client_secret_post")) {
            issues.add("clientAuth.method: client_secret_basic or client_secret_post");
          }
        }
        case ClientAuth.PrivateKeyJwt key -> {
          JWK jwk = key.privateJwk();
          if (jwk == null || !jwk.isPrivate()) {
            issues.add("clientAuth.privateJwk: must be a private key");
          } else if (jwk.getKeyID() == null || jwk.getKeyID().isEmpty()) {
            issues.add("clientAuth.privateJwk: kid is required");
          } else if (!(jwk instanceof com.nimbusds.jose.jwk.ECKey)
              && !(jwk instanceof com.nimbusds.jose.jwk.RSAKey)) {
            issues.add("clientAuth.privateJwk: must be an EC or RSA key");
          }
        }
      }
    }

    private static void range(
        List<String> issues, String name, Duration value, Duration min, Duration max) {
      if (value == null || value.compareTo(min) < 0 || value.compareTo(max) > 0) {
        issues.add(name + ": must be between " + min + " and " + max);
      }
    }
  }

  /** The issuer as a URI (validated). */
  URI issuerUri() {
    return URI.create(Objects.requireNonNull(issuer));
  }
}
