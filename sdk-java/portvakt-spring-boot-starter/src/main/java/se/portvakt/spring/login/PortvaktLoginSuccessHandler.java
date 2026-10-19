package se.portvakt.spring.login;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.time.Instant;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import se.portvakt.spring.web.HttpRequests;

/**
 * After a login: the session state with the new grant (the tokens the callback stored), its
 * absolute end (the ID token's {@code session_exp}, capped by {@code portvakt.login.max-age}) and
 * the first activity; the previous login's tokens of this browser are deleted. The servlet
 * session timeout is set just above the idle timeout (the starter checks the idle timeout itself,
 * counting only protected requests). Then a redirect to {@code returnTo}. Spring Security has
 * already changed the session id (session fixation protection).
 */
public class PortvaktLoginSuccessHandler implements AuthenticationSuccessHandler {
  private final PortvaktSessions sessions;

  public PortvaktLoginSuccessHandler(PortvaktSessions sessions) {
    this.sessions = sessions;
  }

  @Override
  public void onAuthenticationSuccess(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
    PortvaktLoginSettings settings = sessions.settings();
    Instant now = sessions.clock().instant();
    Instant endsAt = now.plus(settings.maxAge());
    if (authentication.getPrincipal() instanceof PortvaktOidcUser user
        && user.getSessionExp() != null
        && user.getSessionExp().isBefore(endsAt)) {
      endsAt = user.getSessionExp();
    }
    HttpSession session = request.getSession();
    String grantId = (String) request.getAttribute(PortvaktAuthorizedClientRepository.NEW_GRANT_ATTRIBUTE);
    if (grantId == null) throw new IllegalStateException("the login callback stored no tokens");
    PortvaktSessionState previous = PortvaktSessionState.of(session);
    if (previous != null && previous.grantId() != null && !previous.grantId().equals(grantId)) {
      sessions.store().delete(previous.grantId());
    }
    sessions.store().expire(grantId, endsAt);
    new PortvaktSessionState(now, endsAt, null, now, grantId).storeIn(session);
    session.setMaxInactiveInterval((int) Math.min(Integer.MAX_VALUE, settings.idleTimeout().toSeconds() + 60));
    String returnTo =
        authentication.getDetails() instanceof PortvaktLoginDetails details ? details.getReturnTo() : null;
    String target = HttpRequests.safeReturnTo(returnTo);
    response.setHeader("Cache-Control", "no-store");
    response.setStatus(303);
    response.setHeader("Location", request.getContextPath() + (target == null ? settings.defaultReturnTo() : target));
  }
}
