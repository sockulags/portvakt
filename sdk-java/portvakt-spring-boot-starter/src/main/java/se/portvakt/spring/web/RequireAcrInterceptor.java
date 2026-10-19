package se.portvakt.spring.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import se.portvakt.sdk.AccessTokenException;
import se.portvakt.spring.PortvaktAuthorizationDecision;
import se.portvakt.spring.PortvaktSecurity;
import se.portvakt.spring.RequireAcr;
import se.portvakt.spring.login.PortvaktLoginResponses;
import se.portvakt.spring.resource.PortvaktJwtAuthenticationToken;

/** Enforces {@link RequireAcr} on Spring MVC handlers. */
public class RequireAcrInterceptor implements HandlerInterceptor {
  private final PortvaktSecurity security;
  private final PortvaktLoginResponses login;

  /** @param login the login's responses, or {@code null} when the browser login is disabled */
  public RequireAcrInterceptor(PortvaktSecurity security, PortvaktLoginResponses login) {
    this.security = security;
    this.login = login;
  }

  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
      throws Exception {
    if (!(handler instanceof HandlerMethod method)) return true;
    RequireAcr required = AnnotatedElementUtils.findMergedAnnotation(method.getMethod(), RequireAcr.class);
    if (required == null) required = AnnotatedElementUtils.findMergedAnnotation(method.getBeanType(), RequireAcr.class);
    if (required == null) return true;
    var authentication = SecurityContextHolder.getContext().getAuthentication();
    PortvaktAuthorizationDecision decision = security.decideAcr(authentication, required.value());
    if (decision.isGranted()) return true;
    boolean bearer = authentication instanceof PortvaktJwtAuthenticationToken;
    if (decision.bearerError() != null) {
      Responses.bearerError(response, decision.bearerError());
    } else if (decision.requiredAcr() != null) {
      if (bearer || login == null) {
        Responses.bearerError(response, AccessTokenException.insufficientUserAuthentication(decision.requiredAcr()));
      } else {
        login.stepUpRequired(request, response, decision.requiredAcr());
      }
    } else if (login != null && !bearer) {
      login.loginRequired(request, response);
    } else {
      Responses.bearerError(response, AccessTokenException.missingToken());
    }
    return false;
  }
}
