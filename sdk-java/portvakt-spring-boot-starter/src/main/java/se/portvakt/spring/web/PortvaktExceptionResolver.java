package se.portvakt.spring.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;
import se.portvakt.sdk.AccessTokenException;
import se.portvakt.sdk.LoginRequiredException;
import se.portvakt.sdk.PortvaktConfigException;
import se.portvakt.sdk.PortvaktException;
import se.portvakt.sdk.PortvaktUnavailableException;
import se.portvakt.spring.login.PortvaktLoginResponses;

/**
 * SDK errors thrown by controllers (for example from {@code PortvaktAccessTokens} or {@code
 * ServiceTokenSource}): {@link LoginRequiredException} becomes a login redirect or 401 {@code
 * login_required}, {@link PortvaktUnavailableException} 503 {@code portvakt_unavailable} with
 * {@code Retry-After}, {@link AccessTokenException} an RFC 6750 answer, other SDK errors their
 * status and code. Configuration errors and everything else pass on.
 */
public class PortvaktExceptionResolver implements HandlerExceptionResolver, Ordered {
  private static final Logger LOG = LoggerFactory.getLogger(PortvaktExceptionResolver.class);

  private final PortvaktLoginResponses login;

  /** @param login the login's responses, or {@code null} when the browser login is disabled */
  public PortvaktExceptionResolver(PortvaktLoginResponses login) {
    this.login = login;
  }

  @Override
  public int getOrder() {
    return Ordered.HIGHEST_PRECEDENCE;
  }

  @Override
  public ModelAndView resolveException(
      HttpServletRequest request, HttpServletResponse response, Object handler, Exception exception) {
    if (!(exception instanceof PortvaktException error) || error instanceof PortvaktConfigException) return null;
    if (response.isCommitted()) return null;
    try {
      if (error instanceof LoginRequiredException && login != null) {
        login.loginRequired(request, response);
      } else if (error instanceof PortvaktUnavailableException) {
        response.setHeader("Retry-After", "5");
        Responses.json(response, 503, Map.of("error", error.code()));
      } else if (error instanceof AccessTokenException bearer) {
        Responses.bearerError(response, bearer);
      } else {
        LOG.warn("Portvakt request failed: {}", error.code());
        Responses.json(response, error.status(), Map.of("error", error.code()));
      }
    } catch (IOException writeFailed) {
      return null;
    }
    return new ModelAndView();
  }
}
