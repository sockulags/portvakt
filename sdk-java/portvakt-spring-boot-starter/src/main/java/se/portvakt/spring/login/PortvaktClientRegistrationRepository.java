package se.portvakt.spring.login;

import java.util.Set;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import se.portvakt.sdk.ClientAuth;
import se.portvakt.sdk.PortvaktConfig;
import se.portvakt.sdk.PortvaktDiscovery;
import se.portvakt.sdk.ProviderMetadata;

/**
 * The tenant's client registration ({@code portvakt}), built lazily from the core's discovery
 * cache: the application starts while Portvakt is down, metadata is refreshed in the background
 * of requests and stale metadata is used while a refresh fails. PKCE is required ({@code
 * ClientSettings.requireProofKey}), as Portvakt requires it for every client. No userinfo
 * endpoint: Portvakt disables it, and the principal comes from the ID token.
 *
 * <p>{@link #findByRegistrationId} throws {@link se.portvakt.sdk.PortvaktUnavailableException}
 * when Portvakt is unreachable and nothing is cached.
 */
public class PortvaktClientRegistrationRepository implements ClientRegistrationRepository {
  private final PortvaktConfig config;
  private final PortvaktDiscovery discovery;
  private final PortvaktLoginSettings settings;
  private volatile Built built;

  private record Built(ProviderMetadata metadata, ClientRegistration registration) {}

  public PortvaktClientRegistrationRepository(
      PortvaktConfig config, PortvaktDiscovery discovery, PortvaktLoginSettings settings) {
    this.config = config;
    this.discovery = discovery;
    this.settings = settings;
  }

  @Override
  public ClientRegistration findByRegistrationId(String registrationId) {
    if (!PortvaktLoginSettings.REGISTRATION_ID.equals(registrationId)) return null;
    ProviderMetadata metadata = discovery.get();
    Built current = built;
    if (current != null && current.metadata == metadata) return current.registration;
    ClientRegistration registration = build(metadata);
    built = new Built(metadata, registration);
    return registration;
  }

  private ClientRegistration build(ProviderMetadata metadata) {
    ClientRegistration.Builder builder =
        ClientRegistration.withRegistrationId(PortvaktLoginSettings.REGISTRATION_ID)
            .clientId(config.clientId())
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri(settings.redirectUri())
            .scope(Set.copyOf(config.scopes()))
            .authorizationUri(metadata.authorizationEndpoint().toString())
            .tokenUri(metadata.tokenEndpoint().toString())
            .jwkSetUri(metadata.jwksUri().toString())
            .issuerUri(config.issuer())
            .userNameAttributeName("sub")
            .providerConfigurationMetadata(metadata.raw())
            .clientName("Portvakt")
            .clientSettings(ClientRegistration.ClientSettings.builder().requireProofKey(true).build());
    switch (config.clientAuth()) {
      case ClientAuth.ClientSecret secret -> {
        builder.clientSecret(secret.clientSecret());
        builder.clientAuthenticationMethod(
            secret.method().equals("client_secret_post")
                ? ClientAuthenticationMethod.CLIENT_SECRET_POST
                : ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
      }
      case ClientAuth.PrivateKeyJwt ignored ->
          builder.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
      case null -> throw new IllegalStateException("portvakt.client-secret or private-jwk is required for the login");
    }
    return builder.build();
  }
}
