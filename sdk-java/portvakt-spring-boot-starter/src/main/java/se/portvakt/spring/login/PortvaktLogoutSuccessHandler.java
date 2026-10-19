package se.portvakt.spring.login;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import java.nio.charset.StandardCharsets;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.util.UriComponentsBuilder;
import se.portvakt.spring.web.HttpRequests;
import se.portvakt.spring.web.Responses;

/**
 * RP-initiated logout ({@code POST {base}/logout}, CSRF-protected by Spring Security while a
 * session exists): after the local session is invalidated, the browser goes to Portvakt's
 * end-session endpoint with {@code id_token_hint}, {@code client_id} and {@code
 * post_logout_redirect_uri}; fetch gets {@code {"redirectTo": url}}. Without a local session (it
 * ended here first, or another tab signed out) the browser still goes there, with {@code
 * client_id} and {@code post_logout_redirect_uri} only: Portvakt's session may be alive, and
 * Portvakt asks the person to confirm without an ID token. When Portvakt is unreachable the
 * person is signed out locally and sent to the post-logout URI.
 */
public class PortvaktLogoutSuccessHandler extends OidcClientInitiatedLogoutSuccessHandler {
  private static final Logger LOG = LoggerFactory.getLogger(PortvaktLogoutSuccessHandler.class);

  private final String localTarget;
  private final ClientRegistrationRepository registrations;
  private final String postLogoutRedirectUri;

  @SuppressWarnings("this-escape")
  public PortvaktLogoutSuccessHandler(
      ClientRegistrationRepository registrations, PortvaktLoginSettings settings) {
    super(registrations);
    setPostLogoutRedirectUri(settings.postLogoutRedirectUri());
    this.localTarget = settings.defaultReturnTo();
    this.registrations = registrations;
    this.postLogoutRedirectUri = settings.postLogoutRedirectUri();
    setDefaultTargetUrl(localTarget);
  }

  /** Portvakt's end-session URL without an ID token, or {@code null} without the endpoint. */
  private String endSessionWithoutIdToken(HttpServletRequest request) {
    ClientRegistration registration = registrations.findByRegistrationId(PortvaktLoginSettings.REGISTRATION_ID);
    if (registration == null) return null;
    Object endpoint = registration.getProviderDetails().getConfigurationMetadata().get("end_session_endpoint");
    if (endpoint == null) return null;
    String baseUrl =
        UriComponentsBuilder.fromUriString(UrlUtils.buildFullRequestUrl(request))
            .replacePath(request.getContextPath())
            .replaceQuery(null)
            .fragment(null)
            .build()
            .toUriString();
    String postLogout = postLogoutRedirectUri.replace("{baseUrl}", baseUrl);
    return UriComponentsBuilder.fromUriString(endpoint.toString())
        .queryParam("client_id", registration.getClientId())
        .queryParam("post_logout_redirect_uri", postLogout)
        .encode(StandardCharsets.UTF_8)
        .build()
        .toUriString();
  }

  @Override
  public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException {
    String target = request.getContextPath() + localTarget;
    if (authentication == null) {
      try {
        String endSession = endSessionWithoutIdToken(request);
        if (endSession != null) target = endSession;
      } catch (RuntimeException unavailable) {
        LOG.warn("RP-initiated logout skipped: {}", unavailable.getClass().getSimpleName());
      }
    } else {
      try {
        String determined = determineTargetUrl(request, response, authentication);
        // Without an end-session endpoint this is the local default: within the context path.
        target = determined.startsWith("/") && !determined.startsWith("//") ? request.getContextPath() + determined : determined;
      } catch (RuntimeException unavailable) {
        // Signed out locally; Portvakt's session stays until it ends on its own.
        LOG.warn("RP-initiated logout skipped: {}", unavailable.getClass().getSimpleName());
      }
    }
    response.setHeader("Cache-Control", "no-store");
    if (HttpRequests.wantsJson(request)) {
      Responses.json(response, 200, Map.of("redirectTo", target));
      return;
    }
    response.setStatus(303);
    response.setHeader("Location", target);
  }
}
