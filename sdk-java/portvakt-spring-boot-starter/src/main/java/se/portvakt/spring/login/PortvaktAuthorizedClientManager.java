package se.portvakt.spring.login;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Spring's {@link OAuth2AuthorizedClientManager} for the browser session's tokens: the check
 * whether the access token needs a refresh, the refresh itself (Spring's refresh token grant
 * through {@link PortvaktRefreshTokenProvider}) and the write of the rotated tokens happen inside
 * one {@link PortvaktTokenStore#update}, so concurrent requests of one session (also stale
 * Spring Session snapshots, also other replicas with the JDBC store) refresh once: the others
 * wait and then see the new tokens. Failures leave the stored tokens as they were.
 */
public class PortvaktAuthorizedClientManager implements OAuth2AuthorizedClientManager {
  private static final List<String> CONTEXT_ATTRIBUTES =
      List.of(PortvaktRefreshTokenProvider.RESPONSE_ATTRIBUTE, PortvaktRefreshTokenProvider.MIN_VALIDITY_ATTRIBUTE);

  private final ClientRegistrationRepository registrations;
  private final PortvaktTokenStore store;
  private final OAuth2AuthorizedClientProvider provider;

  public PortvaktAuthorizedClientManager(
      ClientRegistrationRepository registrations, PortvaktTokenStore store, OAuth2AuthorizedClientProvider provider) {
    this.registrations = registrations;
    this.store = store;
    this.provider = provider;
  }

  @Override
  public OAuth2AuthorizedClient authorize(OAuth2AuthorizeRequest authorizeRequest) {
    if (!PortvaktLoginSettings.REGISTRATION_ID.equals(authorizeRequest.getClientRegistrationId())) return null;
    HttpServletRequest request = requestOf(authorizeRequest);
    PortvaktSessionState state = request == null ? null : PortvaktSessionState.of(request.getSession(false));
    if (state == null || state.grantId() == null) return null;
    ClientRegistration registration = registrations.findByRegistrationId(PortvaktLoginSettings.REGISTRATION_ID);
    Authentication principal = authorizeRequest.getPrincipal();
    PortvaktTokenStore.StoredTokens tokens =
        store.update(
            state.grantId(),
            current -> {
              if (current == null) return null;
              OAuth2AuthorizedClient client =
                  PortvaktAuthorizedClientRepository.toClient(registration, principal.getName(), current);
              OAuth2AuthorizationContext context =
                  OAuth2AuthorizationContext.withAuthorizedClient(client)
                      .principal(principal)
                      .attributes(
                          attributes -> {
                            for (String name : CONTEXT_ATTRIBUTES) {
                              Object value = authorizeRequest.getAttribute(name);
                              if (value != null) attributes.put(name, value);
                            }
                          })
                      .build();
              OAuth2AuthorizedClient refreshed = provider.authorize(context);
              return refreshed == null ? current : PortvaktAuthorizedClientRepository.toTokens(refreshed);
            });
    return tokens == null ? null : PortvaktAuthorizedClientRepository.toClient(registration, principal.getName(), tokens);
  }

  private static HttpServletRequest requestOf(OAuth2AuthorizeRequest authorizeRequest) {
    if (authorizeRequest.getAttribute(HttpServletRequest.class.getName()) instanceof HttpServletRequest request) {
      return request;
    }
    return RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes
        ? attributes.getRequest()
        : null;
  }
}
