package se.portvakt.spring.login;

import java.util.ArrayList;
import java.util.List;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;

/**
 * The browser login's session cookie in a production profile ({@code prod} or {@code
 * production}): it must be {@code Secure} ({@code server.servlet.session.cookie.secure=true}) and
 * have a {@code SameSite} attribute ({@code server.servlet.session.cookie.same-site}, {@code lax}
 * recommended). The starter logs a warning for each problem at start (it cannot know whether a
 * proxy in front terminates TLS and rewrites the cookie, so it does not refuse to start).
 */
public final class PortvaktCookieCheck {
  private PortvaktCookieCheck() {}

  /** The warnings for {@code environment}; empty outside a production profile. */
  public static List<String> warnings(Environment environment) {
    List<String> warnings = new ArrayList<>();
    if (!environment.acceptsProfiles(Profiles.of("prod | production"))) return warnings;
    if (!environment.getProperty("server.servlet.session.cookie.secure", Boolean.class, false)) {
      warnings.add(
          "server.servlet.session.cookie.secure is not true in a production profile: the session cookie"
              + " is sent over plain http too");
    }
    String sameSite = environment.getProperty("server.servlet.session.cookie.same-site");
    if (sameSite == null || sameSite.isBlank()) {
      warnings.add(
          "server.servlet.session.cookie.same-site is not set in a production profile: set it to lax");
    }
    return warnings;
  }
}
