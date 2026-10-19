package se.portvakt.spring.login;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;
import se.portvakt.sdk.PortvaktPrincipal;
import se.portvakt.spring.web.HttpRequests;
import se.portvakt.spring.web.Responses;

/**
 * {@code GET {base}/session}: JSON for scripts, as the TypeScript SDK's: {@code authenticated},
 * {@code principal} (without {@code pin}), {@code expiresAt} (the idle or absolute end, whichever
 * comes first), {@code sessionEndsAt} and {@code csrfToken} (Spring Security's, for the {@code
 * X-CSRF-TOKEN} header of {@code POST {base}/logout}). Never tokens. Reading it is not activity.
 */
public class PortvaktSessionInfoFilter extends OncePerRequestFilter {
  private final PortvaktLoginSettings settings;

  public PortvaktSessionInfoFilter(PortvaktLoginSettings settings) {
    this.settings = settings;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    if (!"GET".equals(request.getMethod()) || !HttpRequests.pathOf(request).equals(settings.sessionPath())) {
      chain.doFilter(request, response);
      return;
    }
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    HttpSession session = request.getSession(false);
    PortvaktSessionState state = PortvaktSessionState.of(session);
    if (!(authentication instanceof OAuth2AuthenticationToken token)
        || !(token.getPrincipal() instanceof PortvaktOidcUser user)
        || state == null) {
      Responses.json(response, 200, Map.of("authenticated", false));
      return;
    }
    Instant expiresAt = state.expiresAt(settings.idleTimeout());
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("authenticated", true);
    body.put("principal", describe(user.getPortvaktPrincipal()));
    body.put("expiresAt", expiresAt.toString());
    body.put("sessionEndsAt", state.endsAt().toString());
    if (request.getAttribute(CsrfToken.class.getName()) instanceof CsrfToken csrf) {
      body.put("csrfToken", csrf.getToken());
    }
    Responses.json(response, 200, body);
  }

  /** The principal as JSON, without the personal identity number. */
  public static Map<String, Object> describe(PortvaktPrincipal principal) {
    Map<String, Object> json = new LinkedHashMap<>();
    json.put("isService", principal.isService());
    json.put("sub", principal.sub());
    json.put("tenant", principal.tenant());
    if (principal.idp() != null) json.put("idp", principal.idp());
    if (principal.idpKind() != null) json.put("idpKind", principal.idpKind().claimValue());
    if (principal.acr() != null) json.put("acr", principal.acr());
    if (principal.authTime() != null) json.put("authTime", principal.authTime().getEpochSecond());
    json.put("roles", principal.roles());
    json.put("attrs", principal.attrs());
    if (principal.rep() != null) {
      Map<String, Object> rep = new LinkedHashMap<>();
      rep.put("sub", principal.rep().sub());
      rep.put("type", principal.rep().type().claimValue());
      if (principal.rep().name() != null) rep.put("name", principal.rep().name());
      json.put("rep", rep);
    }
    if (principal.clientId() != null) json.put("clientId", principal.clientId());
    if (principal.name() != null) json.put("name", principal.name());
    if (principal.email() != null) json.put("email", principal.email());
    if (principal.hsaId() != null) json.put("hsaId", principal.hsaId());
    if (principal.orgAffiliation() != null) json.put("orgAffiliation", principal.orgAffiliation());
    if (principal.protectedIdentity()) json.put("protectedIdentity", true);
    return json;
  }
}
