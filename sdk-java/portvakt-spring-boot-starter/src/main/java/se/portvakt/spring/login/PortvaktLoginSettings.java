package se.portvakt.spring.login;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

/**
 * The browser login's resolved settings (from {@code portvakt.login.*}).
 *
 * @param basePath where the login routes live, such as {@code /auth}
 * @param redirectUri the registered redirect URI (may be a {@code {baseUrl}} template)
 * @param postLogoutRedirectUri the registered post-logout redirect URI (may be a template)
 * @param defaultReturnTo where to go after a login without returnTo
 * @param idleTimeout the servlet session timeout
 * @param maxAge the application's own maximum session age
 * @param outageGrace how long a session survives failed refreshes while Portvakt is down
 * @param publicPaths paths anyone may open in the default filter chain
 */
public record PortvaktLoginSettings(
    String basePath,
    String redirectUri,
    String postLogoutRedirectUri,
    String defaultReturnTo,
    Duration idleTimeout,
    Duration maxAge,
    Duration outageGrace,
    List<String> publicPaths) {

  /** The client registration id of the Portvakt tenant. */
  public static final String REGISTRATION_ID = "portvakt";

  public PortvaktLoginSettings {
    publicPaths = List.copyOf(publicPaths);
  }

  public String loginPath() {
    return basePath + "/login";
  }

  public String stepUpPath() {
    return basePath + "/step-up";
  }

  public String selectRepresentationPath() {
    return basePath + "/select-representation";
  }

  public String callbackPath() {
    return basePath + "/callback";
  }

  public String logoutPath() {
    return basePath + "/logout";
  }

  public String sessionPath() {
    return basePath + "/session";
  }

  /** {@code {base}/login?returnTo=...} */
  public String loginUrl(String returnTo) {
    return loginPath() + "?returnTo=" + encode(returnTo);
  }

  /** {@code {base}/step-up?acr=...&returnTo=...} */
  public String stepUpUrl(String acr, String returnTo) {
    return stepUpPath() + "?acr=" + encode(acr) + "&returnTo=" + encode(returnTo);
  }

  /** {@code {base}/select-representation?returnTo=...} */
  public String selectRepresentationUrl(String returnTo) {
    return selectRepresentationPath() + "?returnTo=" + encode(returnTo);
  }

  private static String encode(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
  }
}
