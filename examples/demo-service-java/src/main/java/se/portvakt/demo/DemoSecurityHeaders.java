package se.portvakt.demo;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import se.portvakt.sdk.PortvaktConfig;
import se.portvakt.sdk.PortvaktClient;

/**
 * The demo's Content-Security-Policy: everything from the demo itself; logout posts a form here
 * and is redirected to Portvakt, so form-action allows the issuer's origin.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
class DemoSecurityHeaders extends OncePerRequestFilter {
  private final String policy;

  DemoSecurityHeaders(PortvaktClient portvakt, DemoProperties properties) {
    PortvaktConfig config = portvakt.config();
    if (properties.production()) {
      if (!config.issuer().startsWith("https://")) throw new IllegalStateException("demo.production: the issuer must be https");
      if (DemoProperties.DEV_CLIENT_SECRET.equals(clientSecret(config))) {
        throw new IllegalStateException("demo.production: the development client secret is refused");
      }
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

  private static String clientSecret(PortvaktConfig config) {
    return config.clientAuth() instanceof se.portvakt.sdk.ClientAuth.ClientSecret secret ? secret.clientSecret() : null;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    response.setHeader("Content-Security-Policy", policy);
    response.setHeader("Referrer-Policy", "no-referrer");
    chain.doFilter(request, response);
  }
}
