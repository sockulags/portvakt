package se.portvakt.spring;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;
import se.portvakt.sdk.AcrRanking;

/**
 * Portvakt settings ({@code portvakt.*}). The tenant settings are shared; browser login, the
 * resource server and service-to-service tokens are enabled independently. Durations accept
 * Spring's formats ({@code 30s}, {@code 10m}, {@code 12h}). Every value is validated at start-up
 * (the core's rules, the same as the TypeScript SDK's); problems are listed without secret
 * values.
 */
@Validated
@ConfigurationProperties(prefix = "portvakt")
public class PortvaktProperties {
  /**
   * The tenant's issuer exactly as Portvakt publishes it: {@code {PUBLIC_URL}/t/{tenant}}, no
   * trailing slash. Tokens are accepted only with this exact {@code iss}: Portvakt's signing keys
   * are shared by every tenant.
   */
  private String issuer;

  /** The application's client_id (also the resource server's default audience). */
  private String clientId;

  /** The client secret (client_secret_basic or client_secret_post); at least 16 characters. */
  private String clientSecret;

  /** How the application authenticates at the token endpoint. */
  @NotNull private ClientAuthMethod clientAuthMethod = ClientAuthMethod.CLIENT_SECRET_BASIC;

  /**
   * For private_key_jwt: the private key as a JWK (JSON, EC P-256 or RSA, with a kid). Its
   * public part must be registered with the application in Portvakt.
   */
  private String privateJwk;

  /** Scopes of a login; must include openid ({@code pin}/{@code hsa} only if allowed). */
  @NotEmpty private List<String> scopes = new ArrayList<>(List.of("openid", "profile", "email"));

  /** Tolerance for exp, nbf and iat (at most 5 minutes). */
  @NotNull private Duration clockSkew = Duration.ofSeconds(30);

  /** Timeout of every request to Portvakt (1 s to 120 s). */
  @NotNull private Duration httpTimeout = Duration.ofSeconds(10);

  /** Discovery metadata is fetched again after this (stale metadata is kept on failure). */
  @NotNull private Duration discoveryCache = Duration.ofHours(1);

  /** With nothing cached, a failed discovery or JWKS fetch is retried after this. */
  @NotNull private Duration failureCache = Duration.ofSeconds(5);

  @Valid private final Jwks jwks = new Jwks();

  /** Assurance levels, lowest first; must match Portvakt's ACR_RANKING. */
  @NotNull private List<String> acrRanking = new ArrayList<>(AcrRanking.DEFAULT.levels());

  /** Allows an http issuer (local development only). */
  private boolean allowInsecureRequests;

  @Valid private final Login login = new Login();

  @Valid private final ResourceServer resourceServer = new ResourceServer();

  @Valid private final ClientCredentials clientCredentials = new ClientCredentials();

  /** Token stores of the browser login. */
  public enum TokenStore {
    MEMORY,
    JDBC
  }

  /** Token endpoint authentication methods. */
  public enum ClientAuthMethod {
    CLIENT_SECRET_BASIC,
    CLIENT_SECRET_POST,
    PRIVATE_KEY_JWT
  }

  /** The JWKS cache. */
  public static class Jwks {
    /** Keys are refetched after this. */
    @NotNull private Duration cacheMaxAge = Duration.ofMinutes(5);

    /** At most one JWKS fetch per this; an unknown kid within it is refused without a fetch. */
    @NotNull private Duration cooldown = Duration.ofSeconds(30);

    /**
     * While refetches fail, keys stay in use until cache-max-age plus this after their last
     * successful fetch; then validation answers 503.
     */
    @NotNull private Duration staleMaxAge = Duration.ofDays(1);

    public Duration getCacheMaxAge() {
      return cacheMaxAge;
    }

    public void setCacheMaxAge(Duration cacheMaxAge) {
      this.cacheMaxAge = cacheMaxAge;
    }

    public Duration getCooldown() {
      return cooldown;
    }

    public void setCooldown(Duration cooldown) {
      this.cooldown = cooldown;
    }

    public Duration getStaleMaxAge() {
      return staleMaxAge;
    }

    public void setStaleMaxAge(Duration staleMaxAge) {
      this.staleMaxAge = staleMaxAge;
    }
  }

  /** Browser login with a server-side session (backend for frontend). */
  public static class Login {
    /** Enables oauth2Login against the tenant issuer and the login routes. */
    private boolean enabled;

    /**
     * Where the login routes live: {@code {base}/login}, {@code /step-up}, {@code
     * /select-representation}, {@code /callback}, {@code /logout} (POST) and {@code /session}.
     */
    @Pattern(regexp = "^(/[A-Za-z0-9._~-]+)+$", message = "must be a path such as /auth, without a trailing slash")
    private String basePath = "/auth";

    /**
     * The registered redirect URI. Default {@code {baseUrl}{base-path}/callback} (the request's
     * origin); set it explicitly behind a proxy.
     */
    private String redirectUri;

    /** The registered post-logout redirect URI. Default {@code {baseUrl}/}. */
    private String postLogoutRedirectUri;

    /** Where to go after a login without returnTo, and after logout without Portvakt. */
    private String defaultReturnTo = "/";

    /**
     * The session ends after this long without activity: a protected request or an access token
     * use (not {@code {base}/session}, public paths or static files).
     */
    @NotNull private Duration idleTimeout = Duration.ofMinutes(30);

    /** The application's own maximum session age; the broker's session_exp caps it further. */
    @NotNull private Duration maxAge = Duration.ofHours(12);

    /**
     * How long a session survives when its access token needs refreshing while Portvakt is
     * unreachable. 0: the session ends at the first failed refresh.
     */
    @NotNull private Duration outageGrace = Duration.ZERO;

    /**
     * Paths anyone may open in the default security filter chain (Ant-style patterns); every
     * other path requires a login.
     */
    private List<String> publicPaths = new ArrayList<>(List.of("/error"));

    /**
     * Where the sessions' tokens live (never in the HTTP session): {@code memory} (one instance)
     * or {@code jdbc} (a DataSource; several instances, Spring Session).
     */
    @NotNull private TokenStore tokenStore = TokenStore.MEMORY;

    /**
     * AES-256-GCM keys sealing the JDBC token store's contents: 32 random bytes each, base64. The
     * first seals, all open (rotation: put the new key first).
     */
    private List<String> tokenEncryptionKey = new ArrayList<>();

    /** The JDBC token store's table. */
    @Pattern(regexp = "^[A-Za-z_][A-Za-z0-9_]{0,62}([.][A-Za-z_][A-Za-z0-9_]{0,62})?$", message = "must be a table name")
    private String tokenStoreTable = "portvakt_grant";

    /** Creates the JDBC token store's table at start-up when missing (otherwise ship the schema). */
    private boolean tokenStoreInitializeSchema;

    /** How often expired tokens and pending logins are deleted. */
    @NotNull private Duration tokenStoreCleanupInterval = Duration.ofMinutes(5);

    /**
     * Allows the in-memory token store although Spring Session is in use (only correct with one
     * instance). By default the start-up fails.
     */
    private boolean allowInMemoryTokenStoreWithSpringSession;

    public TokenStore getTokenStore() {
      return tokenStore;
    }

    public void setTokenStore(TokenStore tokenStore) {
      this.tokenStore = tokenStore;
    }

    public List<String> getTokenEncryptionKey() {
      return tokenEncryptionKey;
    }

    public void setTokenEncryptionKey(List<String> tokenEncryptionKey) {
      this.tokenEncryptionKey = tokenEncryptionKey;
    }

    public String getTokenStoreTable() {
      return tokenStoreTable;
    }

    public void setTokenStoreTable(String tokenStoreTable) {
      this.tokenStoreTable = tokenStoreTable;
    }

    public boolean isTokenStoreInitializeSchema() {
      return tokenStoreInitializeSchema;
    }

    public void setTokenStoreInitializeSchema(boolean tokenStoreInitializeSchema) {
      this.tokenStoreInitializeSchema = tokenStoreInitializeSchema;
    }

    public Duration getTokenStoreCleanupInterval() {
      return tokenStoreCleanupInterval;
    }

    public void setTokenStoreCleanupInterval(Duration tokenStoreCleanupInterval) {
      this.tokenStoreCleanupInterval = tokenStoreCleanupInterval;
    }

    public boolean isAllowInMemoryTokenStoreWithSpringSession() {
      return allowInMemoryTokenStoreWithSpringSession;
    }

    public void setAllowInMemoryTokenStoreWithSpringSession(boolean value) {
      this.allowInMemoryTokenStoreWithSpringSession = value;
    }

    public boolean isEnabled() {
      return enabled;
    }

    public void setEnabled(boolean enabled) {
      this.enabled = enabled;
    }

    public String getBasePath() {
      return basePath;
    }

    public void setBasePath(String basePath) {
      this.basePath = basePath;
    }

    public String getRedirectUri() {
      return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
      this.redirectUri = redirectUri;
    }

    public String getPostLogoutRedirectUri() {
      return postLogoutRedirectUri;
    }

    public void setPostLogoutRedirectUri(String postLogoutRedirectUri) {
      this.postLogoutRedirectUri = postLogoutRedirectUri;
    }

    public String getDefaultReturnTo() {
      return defaultReturnTo;
    }

    public void setDefaultReturnTo(String defaultReturnTo) {
      this.defaultReturnTo = defaultReturnTo;
    }

    public Duration getIdleTimeout() {
      return idleTimeout;
    }

    public void setIdleTimeout(Duration idleTimeout) {
      this.idleTimeout = idleTimeout;
    }

    public Duration getMaxAge() {
      return maxAge;
    }

    public void setMaxAge(Duration maxAge) {
      this.maxAge = maxAge;
    }

    public Duration getOutageGrace() {
      return outageGrace;
    }

    public void setOutageGrace(Duration outageGrace) {
      this.outageGrace = outageGrace;
    }

    public List<String> getPublicPaths() {
      return publicPaths;
    }

    public void setPublicPaths(List<String> publicPaths) {
      this.publicPaths = publicPaths;
    }
  }

  /** Validation of access tokens for the application's own API. */
  public static class ResourceServer {
    /** Enables bearer token validation. */
    private boolean enabled;

    /** The token's aud: this API's client_id. Default: portvakt.client-id. */
    private String audience;

    /**
     * Paths of the resource server filter chain. Default {@code /api/**} when the login is
     * enabled too, otherwise {@code /**}.
     */
    private List<String> paths = new ArrayList<>();

    /** Accept client_credentials tokens from every application of the tenant. */
    private boolean allowService;

    /** Accept client_credentials tokens from these client_ids. */
    private List<String> allowedServices = new ArrayList<>();

    /**
     * Accept person tokens that act for another party (rep). The application must still
     * authorise every action on behalf of rep.sub with its own rules.
     */
    private boolean allowRepresentation = true;

    public boolean isEnabled() {
      return enabled;
    }

    public void setEnabled(boolean enabled) {
      this.enabled = enabled;
    }

    public String getAudience() {
      return audience;
    }

    public void setAudience(String audience) {
      this.audience = audience;
    }

    public List<String> getPaths() {
      return paths;
    }

    public void setPaths(List<String> paths) {
      this.paths = paths;
    }

    public boolean isAllowService() {
      return allowService;
    }

    public void setAllowService(boolean allowService) {
      this.allowService = allowService;
    }

    public List<String> getAllowedServices() {
      return allowedServices;
    }

    public void setAllowedServices(List<String> allowedServices) {
      this.allowedServices = allowedServices;
    }

    public boolean isAllowRepresentation() {
      return allowRepresentation;
    }

    public void setAllowRepresentation(boolean allowRepresentation) {
      this.allowRepresentation = allowRepresentation;
    }
  }

  /** Service-to-service tokens (client_credentials). */
  public static class ClientCredentials {
    /** Exposes a ClientCredentialsTokenProvider bean. */
    private boolean enabled;

    public boolean isEnabled() {
      return enabled;
    }

    public void setEnabled(boolean enabled) {
      this.enabled = enabled;
    }
  }

  public String getIssuer() {
    return issuer;
  }

  public void setIssuer(String issuer) {
    this.issuer = issuer;
  }

  public String getClientId() {
    return clientId;
  }

  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  public String getClientSecret() {
    return clientSecret;
  }

  public void setClientSecret(String clientSecret) {
    this.clientSecret = clientSecret;
  }

  public ClientAuthMethod getClientAuthMethod() {
    return clientAuthMethod;
  }

  public void setClientAuthMethod(ClientAuthMethod clientAuthMethod) {
    this.clientAuthMethod = clientAuthMethod;
  }

  public String getPrivateJwk() {
    return privateJwk;
  }

  public void setPrivateJwk(String privateJwk) {
    this.privateJwk = privateJwk;
  }

  public List<String> getScopes() {
    return scopes;
  }

  public void setScopes(List<String> scopes) {
    this.scopes = scopes;
  }

  public Duration getClockSkew() {
    return clockSkew;
  }

  public void setClockSkew(Duration clockSkew) {
    this.clockSkew = clockSkew;
  }

  public Duration getHttpTimeout() {
    return httpTimeout;
  }

  public void setHttpTimeout(Duration httpTimeout) {
    this.httpTimeout = httpTimeout;
  }

  public Duration getDiscoveryCache() {
    return discoveryCache;
  }

  public void setDiscoveryCache(Duration discoveryCache) {
    this.discoveryCache = discoveryCache;
  }

  public Duration getFailureCache() {
    return failureCache;
  }

  public void setFailureCache(Duration failureCache) {
    this.failureCache = failureCache;
  }

  public Jwks getJwks() {
    return jwks;
  }

  public List<String> getAcrRanking() {
    return acrRanking;
  }

  public void setAcrRanking(List<String> acrRanking) {
    this.acrRanking = acrRanking;
  }

  public boolean isAllowInsecureRequests() {
    return allowInsecureRequests;
  }

  public void setAllowInsecureRequests(boolean allowInsecureRequests) {
    this.allowInsecureRequests = allowInsecureRequests;
  }

  public Login getLogin() {
    return login;
  }

  public ResourceServer getResourceServer() {
    return resourceServer;
  }

  public ClientCredentials getClientCredentials() {
    return clientCredentials;
  }

  @Override
  public String toString() {
    return "PortvaktProperties[issuer=" + issuer + ", clientId=" + clientId + "]";
  }
}
