package se.portvakt.spring.login;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import se.portvakt.spring.web.HttpRequests;
import se.portvakt.spring.web.Responses;

/**
 * The browser login's structured answers: browser navigations are redirected, XHR/fetch gets
 * JSON ({@code 401 {"error": "login_required", "loginUrl"}}, {@code 401 {"error":
 * "step_up_required", "acr", "stepUpUrl"}}).
 */
public final class PortvaktLoginResponses {
  private final PortvaktLoginSettings settings;

  public PortvaktLoginResponses(PortvaktLoginSettings settings) {
    this.settings = settings;
  }

  public PortvaktLoginSettings settings() {
    return settings;
  }

  /** The person must sign in (again). */
  public void loginRequired(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String loginUrl =
        request.getContextPath() + settings.loginUrl(HttpRequests.returnToOf(request, settings.defaultReturnTo()));
    response.setHeader("Cache-Control", "no-store");
    if (HttpRequests.isBrowserNavigation(request)) {
      response.sendRedirect(loginUrl);
      return;
    }
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("error", "login_required");
    body.put("loginUrl", loginUrl);
    Responses.json(response, 401, body);
  }

  /**
   * The session's acr is too low: a step-up to {@code acr} (a navigation from another site gets
   * the interstitial page instead of the redirect).
   */
  public void stepUpRequired(HttpServletRequest request, HttpServletResponse response, String acr) throws IOException {
    String stepUpUrl =
        request.getContextPath()
            + settings.stepUpUrl(acr, HttpRequests.returnToOf(request, settings.defaultReturnTo()));
    response.setHeader("Cache-Control", "no-store");
    if (HttpRequests.isBrowserNavigation(request)) {
      // A deep link from another site: the step-up starts from a page of this application.
      if (SameSiteStart.startedHere(request, settings)) response.sendRedirect(stepUpUrl);
      else Responses.interstitial(response, stepUpUrl);
      return;
    }
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("error", "step_up_required");
    body.put("acr", acr);
    body.put("stepUpUrl", stepUpUrl);
    Responses.json(response, 401, body);
  }

  /** Access denied for another reason (a role, a CSRF failure). */
  public void forbidden(HttpServletRequest request, HttpServletResponse response, String code) throws IOException {
    Responses.error(request, response, 403, code, settings.defaultReturnTo());
  }
}
