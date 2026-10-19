package se.portvakt.spring.login;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Ends a browser session no later than its absolute end (the ID token's {@code session_exp},
 * capped by {@code portvakt.login.max-age}) and after {@code portvakt.login.idle-timeout} without
 * activity. A session past its end is ended (tokens, session, context) before anything else sees
 * it; the request continues unauthenticated. Activity is a protected request: not the login
 * routes, not {@code GET {base}/session}, not the public paths and not static resources, as in
 * the TypeScript SDK where reading the session state is no activity.
 */
public class PortvaktSessionExpiryFilter extends OncePerRequestFilter {
  private static final Logger LOG = LoggerFactory.getLogger(PortvaktSessionExpiryFilter.class);

  private final PortvaktSessions sessions;
  private final RequestMatcher notActivity;

  public PortvaktSessionExpiryFilter(PortvaktSessions sessions, RequestMatcher notActivity) {
    this.sessions = sessions;
    this.notActivity = notActivity;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    HttpSession session = request.getSession(false);
    if (session != null) {
      Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
      if (authentication instanceof OAuth2AuthenticationToken token
          && token.getPrincipal() instanceof PortvaktOidcUser) {
        PortvaktSessionState state = PortvaktSessionState.of(session);
        if (sessions.ended(state)) {
          LOG.debug("Portvakt session ended: session_expired");
          sessions.end(request);
        } else if (!notActivity.matches(request)) {
          sessions.touch(session, state);
        }
      }
    }
    chain.doFilter(request, response);
  }
}
