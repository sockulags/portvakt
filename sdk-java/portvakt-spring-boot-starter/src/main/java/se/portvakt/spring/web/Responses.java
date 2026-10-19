package se.portvakt.spring.web;

import tools.jackson.databind.json.JsonMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import se.portvakt.sdk.AccessTokenException;

/** The SDK's responses: JSON errors, RFC 6750 bearer errors and the Swedish error page. */
public final class Responses {
  private static final JsonMapper JSON = JsonMapper.builder().build();

  private Responses() {}

  /** A JSON body with {@code Cache-Control: no-store}. */
  public static void json(HttpServletResponse response, int status, Object body) throws IOException {
    if (response.isCommitted()) return;
    response.setStatus(status);
    response.setHeader("Cache-Control", "no-store");
    response.setContentType("application/json");
    response.setCharacterEncoding(StandardCharsets.UTF_8.name());
    response.getWriter().write(JSON.writeValueAsString(body));
    response.getWriter().flush();
  }

  /** A 400/401/403 with {@code WWW-Authenticate: Bearer ...} (RFC 6750 section 3). */
  public static void bearerError(HttpServletResponse response, AccessTokenException error) throws IOException {
    if (response.isCommitted()) return;
    response.setHeader("WWW-Authenticate", error.wwwAuthenticate());
    json(response, error.status(), error.body());
  }

  /** 503 while Portvakt's keys cannot be fetched (resource server). */
  public static void temporarilyUnavailable(HttpServletResponse response) throws IOException {
    if (response.isCommitted()) return;
    response.setHeader("Retry-After", "5");
    json(
        response,
        503,
        Map.of(
            "error", "temporarily_unavailable",
            "error_description", "The token cannot be validated right now"));
  }

  /** The {@code Retry-After} value of an unavailable answer: Portvakt's, or 5 seconds. */
  public static String retryAfterSeconds(se.portvakt.sdk.PortvaktUnavailableException unavailable) {
    return unavailable != null && unavailable.retryAfter() != null
        ? String.valueOf(unavailable.retryAfter().toSeconds())
        : "5";
  }

  /** {@code {"error": code}} for fetch, or the error page for a browser. */
  public static void error(
      HttpServletRequest request, HttpServletResponse response, int status, String code, String backTo)
      throws IOException {
    if (response.isCommitted()) return;
    if (status == 503 && response.getHeader("Retry-After") == null) response.setHeader("Retry-After", "5");
    if (HttpRequests.wantsJson(request) || !acceptsHtml(request)) {
      json(response, status, Map.of("error", code));
      return;
    }
    boolean unavailable = status == 503;
    String title = unavailable ? "Inloggningstjänsten är inte tillgänglig just nu" : "Inloggningen kunde inte genomföras";
    String english =
        unavailable
            ? "The sign-in service is unavailable right now. Please try again in a moment."
            : "The sign-in could not be completed.";
    if (status == 403 && !code.equals("acr_not_met") && !code.equals("cross_site_request")) {
      title = "Åtkomst nekad";
      english = "Access denied.";
    }
    String page =
        String.join(
            "\n",
            "<!doctype html>",
            "<html lang=\"sv\"><head><meta charset=\"utf-8\">",
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
            "<title>" + escapeHtml(title) + "</title></head><body>",
            "<h1>" + escapeHtml(title) + "</h1>",
            "<p lang=\"en\">" + escapeHtml(english) + "</p>",
            "<p>Felkod / error code: <code data-testid=\"portvakt-error-code\">" + escapeHtml(code) + "</code></p>",
            "<p><a href=\"" + escapeHtml(backTo) + "\">Tillbaka / Back</a></p>",
            "</body></html>");
    response.setStatus(status);
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
    response.setContentType("text/html");
    response.setCharacterEncoding(StandardCharsets.UTF_8.name());
    response.getWriter().write(page);
    response.getWriter().flush();
  }

  /**
   * The page a browser navigation from another site gets instead of a step-up, a representation
   * switch or a login that would replace the session: minimal HTML of the application (no
   * styles, no script, strict CSP) with a button that sends the same GET from here, so the flow
   * starts same-site. {@code target} is a same-origin path (with the context path) and query.
   */
  public static void interstitial(HttpServletResponse response, String target) throws IOException {
    if (response.isCommitted()) return;
    int query = target.indexOf('?');
    String path = query < 0 ? target : target.substring(0, query);
    StringBuilder fields = new StringBuilder();
    if (query >= 0) {
      for (String pair : target.substring(query + 1).split("&")) {
        if (pair.isEmpty()) continue;
        int equals = pair.indexOf('=');
        String name = decode(equals < 0 ? pair : pair.substring(0, equals));
        String value = equals < 0 ? "" : decode(pair.substring(equals + 1));
        fields
            .append("<input type=\"hidden\" name=\"")
            .append(escapeHtml(name))
            .append("\" value=\"")
            .append(escapeHtml(value))
            .append("\">");
      }
    }
    String page =
        String.join(
            "\n",
            "<!doctype html>",
            "<html lang=\"sv\"><head><meta charset=\"utf-8\">",
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
            "<meta name=\"robots\" content=\"noindex\">",
            "<title>Fortsätt till inloggning</title></head><body>",
            "<h1>Fortsätt till inloggning</h1>",
            "<p>Du kom hit från en annan webbplats. Fortsätt för att logga in här.</p>",
            "<p lang=\"en\">You came here from another site. Continue to sign in here.</p>",
            "<form method=\"get\" action=\"" + escapeHtml(path) + "\">" + fields,
            "<button type=\"submit\" data-testid=\"portvakt-continue\">Fortsätt till inloggning</button>",
            "</form>",
            "</body></html>");
    response.setStatus(200);
    response.setHeader("Cache-Control", "no-store");
    response.setHeader(
        "Content-Security-Policy", "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    // The button's request must carry this origin when the browser sends no Sec-Fetch-Site.
    response.setHeader("Referrer-Policy", "same-origin");
    response.setHeader("X-Frame-Options", "DENY");
    response.setContentType("text/html");
    response.setCharacterEncoding(StandardCharsets.UTF_8.name());
    response.getWriter().write(page);
    response.getWriter().flush();
  }

  private static String decode(String value) {
    try {
      return java.net.URLDecoder.decode(value, StandardCharsets.UTF_8);
    } catch (IllegalArgumentException malformed) {
      return "";
    }
  }

  private static boolean acceptsHtml(HttpServletRequest request) {
    if (HttpRequests.isBrowserNavigation(request)) return true;
    String accept = request.getHeader("Accept");
    return accept == null || accept.contains("text/html") || accept.contains("*/*");
  }

  /** Escapes text for an HTML page. */
  public static String escapeHtml(String value) {
    StringBuilder out = new StringBuilder(value.length());
    for (char c : value.toCharArray()) {
      switch (c) {
        case '&', '<', '>', '"', '\'' -> out.append("&#").append((int) c).append(';');
        default -> out.append(c);
      }
    }
    return out.toString();
  }

  /** Serialises a value with the SDK's JSON mapper. */
  public static String toJson(Object value) throws IOException {
    return JSON.writeValueAsString(value);
  }
}
