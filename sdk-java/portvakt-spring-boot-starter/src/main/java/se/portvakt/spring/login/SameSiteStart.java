package se.portvakt.spring.login;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.Locale;
import se.portvakt.spring.web.HttpRequests;

/**
 * Whether a request that would replace the session's login (a step-up, a representation switch,
 * a login with {@code acr} or {@code prompt}, any login over a session) was started by the
 * application itself: {@code Sec-Fetch-Site} {@code same-origin} or {@code none} (typed or
 * bookmarked) when the browser sends it, otherwise a {@code Referer} of the application's own
 * origin (the redirect URI's, or the request's when that is a template).
 */
final class SameSiteStart {
  private SameSiteStart() {}

  static boolean startedHere(HttpServletRequest request, PortvaktLoginSettings settings) {
    String site = request.getHeader("Sec-Fetch-Site");
    if (site != null && !site.isEmpty()) return site.equals("same-origin") || site.equals("none");
    String referer = request.getHeader("Referer");
    if (referer == null) return false;
    try {
      URI uri = URI.create(referer);
      if (uri.getScheme() == null || uri.getHost() == null) return false;
      String origin = uri.getScheme() + "://" + uri.getHost() + (uri.getPort() < 0 ? "" : ":" + uri.getPort());
      return normalise(ownOrigin(request, settings)).equals(normalise(origin));
    } catch (IllegalArgumentException notAUrl) {
      return false;
    }
  }

  private static String ownOrigin(HttpServletRequest request, PortvaktLoginSettings settings) {
    String redirect = settings.redirectUri();
    if (redirect.startsWith("{")) return HttpRequests.originOf(request);
    URI uri = URI.create(redirect);
    return uri.getScheme() + "://" + uri.getHost() + (uri.getPort() < 0 ? "" : ":" + uri.getPort());
  }

  private static String normalise(String origin) {
    return origin
        .toLowerCase(Locale.ROOT)
        .replaceFirst("^http://([^/]+):80$", "http://$1")
        .replaceFirst("^https://([^/]+):443$", "https://$1");
  }
}
