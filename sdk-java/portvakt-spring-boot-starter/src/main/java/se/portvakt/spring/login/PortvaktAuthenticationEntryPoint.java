package se.portvakt.spring.login;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

/** Unauthenticated requests of the login chain: a redirect to the login, or 401 JSON for XHR. */
public class PortvaktAuthenticationEntryPoint implements AuthenticationEntryPoint {
  private final PortvaktLoginResponses responses;

  public PortvaktAuthenticationEntryPoint(PortvaktLoginResponses responses) {
    this.responses = responses;
  }

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
      throws IOException {
    responses.loginRequired(request, response);
  }
}
