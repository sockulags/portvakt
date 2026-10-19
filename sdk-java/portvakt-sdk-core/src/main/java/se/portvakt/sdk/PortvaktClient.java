package se.portvakt.sdk;

/**
 * One Portvakt client per application: the shared discovery cache, JWKS cache, token verifier
 * and client_credentials provider. Create it once and reuse it; it is thread-safe and contacts
 * Portvakt lazily.
 *
 * <pre>{@code
 * PortvaktClient portvakt = PortvaktClient.create(PortvaktConfig.builder()
 *     .issuer("https://login.example.org/t/kommunen")
 *     .clientId("case-service")
 *     .clientAuth(ClientAuth.clientSecretBasic(secret))
 *     .build());
 * PortvaktPrincipal caller = portvakt.verifier().verifyAccessToken(token, "case-service");
 * }</pre>
 */
public final class PortvaktClient {
  private final PortvaktConfig config;
  private final PortvaktDiscovery discovery;
  private final PortvaktJwks jwks;
  private final PortvaktTokenVerifier verifier;
  private volatile ClientCredentialsTokenProvider clientCredentials;

  private PortvaktClient(PortvaktConfig config) {
    this.config = config;
    this.discovery = new PortvaktDiscovery(config);
    this.jwks = new PortvaktJwks(config, () -> discovery.get().jwksUri());
    this.verifier = new PortvaktTokenVerifier(config, jwks);
  }

  public static PortvaktClient create(PortvaktConfig config) {
    return new PortvaktClient(config);
  }

  public PortvaktConfig config() {
    return config;
  }

  public PortvaktDiscovery discovery() {
    return discovery;
  }

  public PortvaktJwks jwks() {
    return jwks;
  }

  public PortvaktTokenVerifier verifier() {
    return verifier;
  }

  /**
   * The client_credentials provider.
   *
   * @throws PortvaktConfigException when no {@code clientAuth} is configured
   */
  public ClientCredentialsTokenProvider clientCredentials() {
    ClientCredentialsTokenProvider provider = clientCredentials;
    if (provider == null) {
      synchronized (this) {
        provider = clientCredentials;
        if (provider == null) {
          provider = new ClientCredentialsTokenProvider(config, discovery);
          clientCredentials = provider;
        }
      }
    }
    return provider;
  }
}
