package se.portvakt.spring.login;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.csrf.CsrfException;
import se.portvakt.spring.PortvaktAuthorizationDecision;

/**
 * Denied requests of the login chain: an acr requirement ({@code
 * PortvaktSecurity.requireAcr}) sends the person to the step-up (401 {@code step_up_required}
 * for XHR); a CSRF failure answers 403 {@code invalid_csrf_token}; anything else 403 {@code
 * forbidden}.
 */
public class PortvaktAccessDeniedHandler implements AccessDeniedHandler {
  private final PortvaktLoginResponses responses;

  public PortvaktAccessDeniedHandler(PortvaktLoginResponses responses) {
    this.responses = responses;
  }

  @Override
  public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException denied)
      throws IOException {
    if (denied instanceof AuthorizationDeniedException authorization
        && authorization.getAuthorizationResult() instanceof PortvaktAuthorizationDecision decision
        && decision.requiredAcr() != null) {
      responses.stepUpRequired(request, response, decision.requiredAcr());
      return;
    }
    responses.forbidden(request, response, denied instanceof CsrfException ? "invalid_csrf_token" : "forbidden");
  }
}
