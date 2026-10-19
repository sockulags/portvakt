package se.portvakt.demo;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import se.portvakt.sdk.PortvaktConfig;
import se.portvakt.sdk.PortvaktClient;

/**
 * The demo's Content-Security-Policy: everything from the demo itself; logout posts a form here
 * and is redirected to Portvakt, so form-action allows the issuer's origin. Also no cross-origin
 * window references (COOP) and no powerful browser features. Spring Security adds the rest
 * (X-Frame-Options DENY, nosniff, no-cache for secured responses, HSTS over https).
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
class DemoSecurityHeaders extends OncePerRequestFilter {
  private final String policy;

  DemoSecurityHeaders(PortvaktClient portvakt, DemoProperties properties, Environment environment) {
    PortvaktConfig config = portvakt.config();
    if (properties.production()) {
      List<String> issues = productionIssues(config, environment);
      if (!issues.isEmpty()) throw new IllegalStateException("demo.production: " + String.join("; ", issues));
    }
    URI issuer = URI.create(config.issuer());
    String origin = issuer.getScheme() + "://" + issuer.getHost() + (issuer.getPort() < 0 ? "" : ":" + issuer.getPort());
    this.policy =
        String.join(
            "; ",
            "default-src 'self'",
            "img-src 'self' data:",
            "object-src 'none'",
            "base-uri 'none'",
            "frame-ancestors 'none'",
            "form-action 'self' " + origin);
  }

  /** What {@code demo.production=true} refuses: development values and insecure transport. */
  static List<String> productionIssues(PortvaktConfig config, Environment environment) {
    List<String> issues = new ArrayList<>();
    if (!config.issuer().startsWith("https://")) issues.add("the issuer must be https");
    if (config.allowInsecureRequests()) issues.add("portvakt.allow-insecure-requests must be false");
    if (DemoProperties.DEV_CLIENT_SECRET.equals(clientSecret(config))) {
      issues.add("the development client secret is refused");
    }
    if (!environment.getProperty("server.servlet.session.cookie.secure", Boolean.class, false)) {
      issues.add("the session cookie must be Secure (server.servlet.session.cookie.secure)");
    }
    String sameSite = environment.getProperty("server.servlet.session.cookie.same-site");
    if (sameSite == null || sameSite.isBlank() || sameSite.equalsIgnoreCase("none")) {
      issues.add("the session cookie needs SameSite lax or strict");
    }
    return issues;
  }

  private static String clientSecret(PortvaktConfig config) {
    return config.clientAuth() instanceof se.portvakt.sdk.ClientAuth.ClientSecret secret ? secret.clientSecret() : null;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    response.setHeader("Content-Security-Policy", policy);
    response.setHeader("Referrer-Policy", "no-referrer");
    response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    response.setHeader("Permissions-Policy", "camera=(), geolocation=(), microphone=(), payment=(), usb=()");
    chain.doFilter(request, response);
  }
}
