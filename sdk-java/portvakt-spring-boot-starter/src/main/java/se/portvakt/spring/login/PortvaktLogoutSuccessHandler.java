package se.portvakt.spring.login;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import se.portvakt.spring.web.HttpRequests;
import se.portvakt.spring.web.Responses;

/**
 * RP-initiated logout ({@code POST {base}/logout}, CSRF-protected by Spring Security): after the
 * local session is invalidated, the browser goes to Portvakt's end-session endpoint with {@code
 * id_token_hint} and {@code post_logout_redirect_uri}; fetch gets {@code {"redirectTo": url}}.
 * When Portvakt is unreachable the person is signed out locally and sent to the post-logout URI.
 */
public class PortvaktLogoutSuccessHandler extends OidcClientInitiatedLogoutSuccessHandler {
  private static final Logger LOG = LoggerFactory.getLogger(PortvaktLogoutSuccessHandler.class);

  private final String localTarget;

  @SuppressWarnings("this-escape")
  public PortvaktLogoutSuccessHandler(
      ClientRegistrationRepository registrations, PortvaktLoginSettings settings) {
    super(registrations);
    setPostLogoutRedirectUri(settings.postLogoutRedirectUri());
    this.localTarget = settings.defaultReturnTo();
    setDefaultTargetUrl(localTarget);
  }

  @Override
  public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException {
    String target = request.getContextPath() + localTarget;
    if (authentication != null) {
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
