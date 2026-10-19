package se.portvakt.spring.login;

import se.portvakt.sdk.PortvaktException;

/**
 * A browser navigation from another site to a route that would replace the session's login (a
 * step-up, a representation switch, a login with {@code acr} or {@code prompt}, a login over a
 * session): answered with the interstitial page ({@code Responses.interstitial}), whose button
 * starts the same route from the application itself.
 */
public class CrossSiteNavigationException extends PortvaktException {
  private static final long serialVersionUID = 1L;

  private final String target;

  /** @param target the route to start from the interstitial: path (with context path) and query */
  public CrossSiteNavigationException(String target) {
    super("cross_site_request", "started from another site", 200);
    this.target = target;
  }

  public String target() {
    return target;
  }
}
