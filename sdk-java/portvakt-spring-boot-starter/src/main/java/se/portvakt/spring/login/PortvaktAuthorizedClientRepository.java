package se.portvakt.spring.login;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import se.portvakt.spring.web.HttpRequests;

/**
 * Spring's authorized clients on top of the {@link PortvaktTokenStore}: the HTTP session holds
 * only the grant id ({@link PortvaktSessionState}), never the tokens or the client registration
 * (with its secret). The login callback's save makes a new grant (its id is handed to the
 * success handler as the request attribute {@link #NEW_GRANT_ATTRIBUTE}); a later save replaces
 * the session's grant.
 */
public class PortvaktAuthorizedClientRepository implements OAuth2AuthorizedClientRepository {
  /** Request attribute: the grant id the login callback just created. */
  public static final String NEW_GRANT_ATTRIBUTE = PortvaktAuthorizedClientRepository.class.getName() + ".newGrant";

  private static final SecureRandom RANDOM = new SecureRandom();

  private final PortvaktTokenStore store;
  private final ClientRegistrationRepository registrations;
  private final PortvaktLoginSettings settings;
  private final Clock clock;

  public PortvaktAuthorizedClientRepository(
      PortvaktTokenStore store, ClientRegistrationRepository registrations, PortvaktLoginSettings settings, Clock clock) {
    this.store = store;
    this.registrations = registrations;
    this.settings = settings;
    this.clock = clock;
  }

  /** A random grant id (256 bits). */
  public static String newGrantId() {
    byte[] bytes = new byte[32];
    RANDOM.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  @Override
  @SuppressWarnings("unchecked")
  public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(
      String registrationId, Authentication principal, HttpServletRequest request) {
    if (!PortvaktLoginSettings.REGISTRATION_ID.equals(registrationId)) return null;
    PortvaktSessionState state = PortvaktSessionState.of(request.getSession(false));
    if (state == null || state.grantId() == null) return null;
    PortvaktTokenStore.StoredTokens tokens = store.load(state.grantId());
    if (tokens == null) return null;
    return (T) toClient(registrations.findByRegistrationId(registrationId), principal.getName(), tokens);
  }

  @Override
  public void saveAuthorizedClient(
      OAuth2AuthorizedClient client, Authentication principal, HttpServletRequest request, HttpServletResponse response) {
    PortvaktTokenStore.StoredTokens tokens = toTokens(client);
    PortvaktSessionState state = PortvaktSessionState.of(request.getSession(false));
    boolean callback = HttpRequests.pathOf(request).equals(settings.callbackPath());
    if (callback || state == null || state.grantId() == null) {
      String grantId = newGrantId();
      store.save(grantId, tokens, clock.instant().plus(settings.maxAge()));
      request.setAttribute(NEW_GRANT_ATTRIBUTE, grantId);
      return;
    }
    PortvaktTokenStore.StoredTokens previous = store.load(state.grantId());
    store.save(state.grantId(), tokens.withIdToken(previous == null ? null : previous.idToken()), state.endsAt());
  }

  @Override
  public void removeAuthorizedClient(
      String registrationId, Authentication principal, HttpServletRequest request, HttpServletResponse response) {
    PortvaktSessionState state = PortvaktSessionState.of(request.getSession(false));
    if (state != null && state.grantId() != null) store.delete(state.grantId());
  }

  public static OAuth2AuthorizedClient toClient(
      ClientRegistration registration, String principalName, PortvaktTokenStore.StoredTokens tokens) {
    OAuth2AccessToken access =
        new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER, tokens.accessToken(), tokens.issuedAt(), tokens.expiresAt(), tokens.scopes());
    OAuth2RefreshToken refresh = tokens.refreshToken() == null ? null : new OAuth2RefreshToken(tokens.refreshToken(), null);
    return new OAuth2AuthorizedClient(registration, principalName, access, refresh);
  }

  public static PortvaktTokenStore.StoredTokens toTokens(OAuth2AuthorizedClient client) {
    OAuth2AccessToken access = client.getAccessToken();
    return new PortvaktTokenStore.StoredTokens(
        access.getTokenValue(),
        access.getIssuedAt(),
        access.getExpiresAt(),
        access.getScopes(),
        client.getRefreshToken() == null ? null : client.getRefreshToken().getTokenValue());
  }
}
