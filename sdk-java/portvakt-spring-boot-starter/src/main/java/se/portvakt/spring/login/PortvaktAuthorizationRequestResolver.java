package se.portvakt.spring.login;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.net.URI;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DeferredCsrfToken;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import se.portvakt.sdk.PortvaktException;
import se.portvakt.spring.web.HttpRequests;

/**
 * The login routes (GET only): {@code {base}/login}, {@code {base}/step-up} and {@code
 * {base}/select-representation}. Each starts an authorization code flow with PKCE (required by
 * the client registration), state and nonce (Spring's), and adds:
 *
 * <ul>
 *   <li>{@code acr_values} for a step-up ({@code acr} is required) or a login with {@code acr};
 *       the callback refuses a login that did not reach it ({@code acr_not_met}) and keeps the
 *       existing session;
 *   <li>{@code prompt=select_account} for the representation switch (the chooser again without a
 *       new upstream login); a plain login passes {@code prompt} ({@code login}, {@code
 *       select_account}, {@code none});
 *   <li>{@code login_hint} ({@code loginHint}) and {@code ui_locales} ({@code uiLocales}).
 * </ul>
 *
 * {@code returnTo} must be a same-origin path. A step-up or representation switch replaces the
 * session's login, so another site must not be able to start one; the same holds for a login with
 * {@code acr} or {@code prompt}, and for any login while a session exists: {@code Sec-Fetch-Site}
 * must be {@code same-origin} or {@code none} when the browser sends it; otherwise a same-origin
 * {@code Referer} or the session's CSRF token as {@code csrf} is required. A plain login without
 * a session may be started from anywhere (a link to "Logga in").
 */
public class PortvaktAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {
  /** Authorization request attribute: {@code login}, {@code step_up}, {@code select_representation}. */
  public static final String KIND_ATTRIBUTE = "portvakt.kind";
  /** Authorization request attribute: the acr the login must reach. */
  public static final String ACR_ATTRIBUTE = "portvakt.acr";
  /** Authorization request attribute: where to go after the login. */
  public static final String RETURN_TO_ATTRIBUTE = "portvakt.returnTo";

  private static final Pattern ACR = Pattern.compile("^[\\x21-\\x7e]{1,255}$");
  private static final Pattern UI_LOCALES =
      Pattern.compile("^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*( [A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*)*$");
  private static final Set<String> PROMPTS = Set.of("login", "select_account", "none");
  private static final Set<String> PARAMETERS = Set.of("returnTo", "acr", "prompt", "loginHint", "csrf", "uiLocales");

  private record Request(String kind, String returnTo, String acr, Map<String, Object> parameters) {}

  private static final ThreadLocal<Request> CURRENT = new ThreadLocal<>();

  private final DefaultOAuth2AuthorizationRequestResolver delegate;
  private final PortvaktLoginSettings settings;

  public PortvaktAuthorizationRequestResolver(
      ClientRegistrationRepository registrations, PortvaktLoginSettings settings) {
    this.settings = settings;
    this.delegate = new DefaultOAuth2AuthorizationRequestResolver(registrations, settings.basePath() + "/oauth2");
    this.delegate.setAuthorizationRequestCustomizer(
        builder -> {
          Request current = CURRENT.get();
          if (current == null) return;
          builder.additionalParameters(parameters -> parameters.putAll(current.parameters));
          builder.attributes(
              attributes -> {
                attributes.put(KIND_ATTRIBUTE, current.kind);
                attributes.put(RETURN_TO_ATTRIBUTE, current.returnTo);
                if (current.acr != null) attributes.put(ACR_ATTRIBUTE, current.acr);
              });
        });
  }

  @Override
  public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
    if (!"GET".equals(request.getMethod())) return null;
    String path = HttpRequests.pathOf(request);
    String kind;
    if (path.equals(settings.loginPath())) kind = "login";
    else if (path.equals(settings.stepUpPath())) kind = "step_up";
    else if (path.equals(settings.selectRepresentationPath())) kind = "select_representation";
    else return null;
    return resolveKind(request, kind);
  }

  @Override
  public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
    return resolve(request);
  }

  private OAuth2AuthorizationRequest resolveKind(HttpServletRequest request, String kind) {
    Map<String, String> query = new LinkedHashMap<>();
    for (String name : PARAMETERS) {
      String[] values = request.getParameterValues(name);
      if (values == null) continue;
      if (values.length != 1) throw invalid();
      query.put(name, values[0]);
    }
    String acr = query.get("acr");
    if (acr != null && !ACR.matcher(acr).matches()) throw invalid();
    String prompt = query.get("prompt");
    if (prompt != null && !PROMPTS.contains(prompt)) throw invalid();
    String loginHint = query.get("loginHint");
    if (loginHint != null
        && (loginHint.isEmpty() || loginHint.length() > 320 || HttpRequests.hasControlCharacters(loginHint, false))) {
      throw invalid();
    }
    String uiLocales = query.get("uiLocales");
    if (uiLocales != null && (uiLocales.length() > 100 || !UI_LOCALES.matcher(uiLocales).matches())) throw invalid();
    String csrf = query.get("csrf");
    if (csrf != null && csrf.length() > 256) throw invalid();
    if (query.containsKey("returnTo") && query.get("returnTo").length() > 4096) throw invalid();
    if (kind.equals("step_up") && acr == null) {
      throw new PortvaktException("invalid_request", "acr is required for a step-up", 400);
    }
    // A step-up, a representation switch, and a login that asks for an acr or a prompt, or that
    // would replace an existing session, must come from the application itself.
    boolean replacesOrSteers =
        !kind.equals("login")
            || acr != null
            || prompt != null
            || PortvaktSessionState.of(request.getSession(false)) != null;
    if (replacesOrSteers) requireSameSiteInitiation(request, csrf);

    String returnTo = HttpRequests.safeReturnTo(query.get("returnTo"));
    if (returnTo == null) returnTo = settings.defaultReturnTo();
    Map<String, Object> parameters = new LinkedHashMap<>();
    String requiredAcr = kind.equals("select_representation") ? null : acr;
    if (requiredAcr != null) parameters.put("acr_values", requiredAcr);
    if (kind.equals("select_representation")) parameters.put("prompt", "select_account");
    else if (kind.equals("login") && prompt != null) parameters.put("prompt", prompt);
    if (loginHint != null) parameters.put("login_hint", loginHint);
    if (uiLocales != null) parameters.put("ui_locales", uiLocales);

    CURRENT.set(new Request(kind, returnTo, requiredAcr, parameters));
    try {
      OAuth2AuthorizationRequest resolved = delegate.resolve(request, PortvaktLoginSettings.REGISTRATION_ID);
      if (resolved == null) throw new IllegalStateException("the Portvakt client registration is missing");
      return resolved;
    } finally {
      CURRENT.remove();
    }
  }

  private void requireSameSiteInitiation(HttpServletRequest request, String csrf) {
    String site = request.getHeader("Sec-Fetch-Site");
    if (site != null && !site.isEmpty()) {
      if (site.equals("same-origin") || site.equals("none")) return;
      throw crossSite();
    }
    String referer = request.getHeader("Referer");
    if (referer != null) {
      try {
        URI uri = URI.create(referer);
        String origin = uri.getScheme() + "://" + uri.getHost() + (uri.getPort() < 0 ? "" : ":" + uri.getPort());
        if (sameOrigin(origin, request)) return;
      } catch (IllegalArgumentException notAUrl) {
        // Fall through to the CSRF token.
      }
    }
    if (csrf != null && csrfMatches(request, csrf)) return;
    throw crossSite();
  }

  private boolean sameOrigin(String origin, HttpServletRequest request) {
    String own = HttpRequests.originOf(request);
    String redirect = settings.redirectUri();
    if (!redirect.startsWith("{")) {
      URI uri = URI.create(redirect);
      own = uri.getScheme() + "://" + uri.getHost() + (uri.getPort() < 0 ? "" : ":" + uri.getPort());
    }
    return normalise(own).equals(normalise(origin));
  }

  private static String normalise(String origin) {
    return origin.toLowerCase(java.util.Locale.ROOT).replaceFirst("^http://([^/]+):80$", "http://$1")
        .replaceFirst("^https://([^/]+):443$", "https://$1");
  }

  /** The session's CSRF token (Spring Security's), raw or in its masked (XOR) form. */
  private static boolean csrfMatches(HttpServletRequest request, String presented) {
    Object deferred = request.getAttribute(DeferredCsrfToken.class.getName());
    if (!(deferred instanceof DeferredCsrfToken token) || token.isGenerated()) return false;
    CsrfToken raw = token.get();
    if (raw == null) return false;
    if (constantTimeEquals(presented, raw.getToken())) return true;
    HttpServletRequestWrapper wrapper =
        new HttpServletRequestWrapper(request) {
          @Override
          public String getHeader(String name) {
            return name.equalsIgnoreCase(raw.getHeaderName()) ? null : super.getHeader(name);
          }

          @Override
          public String getParameter(String name) {
            return name.equals(raw.getParameterName()) ? presented : super.getParameter(name);
          }
        };
    String resolved = new XorCsrfTokenRequestAttributeHandler().resolveCsrfTokenValue(wrapper, raw);
    return resolved != null && constantTimeEquals(resolved, raw.getToken());
  }

  private static boolean constantTimeEquals(String a, String b) {
    return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
  }

  private static PortvaktException invalid() {
    return new PortvaktException("invalid_request", "invalid login parameters", 400);
  }

  private static PortvaktException crossSite() {
    return new PortvaktException("cross_site_request", "started from another site", 403);
  }
}
