package se.portvakt.spring.login;

import java.time.Clock;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import se.portvakt.sdk.AcrRanking;

/**
 * Everything {@link PortvaktLoginConfigurer} wires into Spring Security's oauth2Login, as one
 * bean. Override the bean to replace a part (for example the failure handler's page).
 *
 * @param settings the resolved login settings
 * @param registrations the tenant's client registration
 * @param authorizedClients the session's tokens in the token store (the session holds the grant id)
 * @param authorizationRequests pending logins, single use, in the token store
 * @param resolver the login routes
 * @param codeTokenClient the code exchange (PKCE, client authentication, timeouts)
 * @param userService the principal from the ID token only
 * @param successHandler records the session's end and redirects to returnTo
 * @param failureHandler error pages and JSON
 * @param logoutSuccessHandler RP-initiated logout
 * @param responses login redirects, step-up and structured 401/403
 * @param sessions ending and touching sessions
 * @param ranking the acr ranking
 * @param clock the clock
 */
public record PortvaktLoginComponents(
    PortvaktLoginSettings settings,
    ClientRegistrationRepository registrations,
    OAuth2AuthorizedClientRepository authorizedClients,
    PortvaktAuthorizationRequestRepository authorizationRequests,
    PortvaktAuthorizationRequestResolver resolver,
    OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> codeTokenClient,
    PortvaktOidcUserService userService,
    PortvaktLoginSuccessHandler successHandler,
    PortvaktLoginFailureHandler failureHandler,
    PortvaktLogoutSuccessHandler logoutSuccessHandler,
    PortvaktLoginResponses responses,
    PortvaktSessions sessions,
    AcrRanking ranking,
    Clock clock) {}
