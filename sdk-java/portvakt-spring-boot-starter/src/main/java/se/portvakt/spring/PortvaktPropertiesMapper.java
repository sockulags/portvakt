package se.portvakt.spring;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import se.portvakt.sdk.AccessTokenRequirements;
import se.portvakt.sdk.AcrRanking;
import se.portvakt.sdk.ClientAuth;
import se.portvakt.sdk.PortvaktConfig;
import se.portvakt.sdk.PortvaktConfigException;
import se.portvakt.spring.login.PortvaktLoginSettings;
import se.portvakt.spring.web.HttpRequests;

/** {@code portvakt.*} properties to the core configuration, validated together. */
final class PortvaktPropertiesMapper {
  private static final Map<String, String> PROPERTY_NAMES =
      Map.ofEntries(
          Map.entry("issuer", "portvakt.issuer"),
          Map.entry("clientId", "portvakt.client-id"),
          Map.entry("clientAuth.clientSecret", "portvakt.client-secret"),
          Map.entry("clientAuth.privateJwk", "portvakt.private-jwk"),
          Map.entry("clientAuth.method", "portvakt.client-auth-method"),
          Map.entry("scopes", "portvakt.scopes"),
          Map.entry("clockSkew", "portvakt.clock-skew"),
          Map.entry("httpTimeout", "portvakt.http-timeout"),
          Map.entry("discoveryCacheTtl", "portvakt.discovery-cache"),
          Map.entry("failureCacheTtl", "portvakt.failure-cache"),
          Map.entry("jwksCacheMaxAge", "portvakt.jwks.cache-max-age"),
          Map.entry("jwksCooldown", "portvakt.jwks.cooldown"),
          Map.entry("jwksStaleMaxAge", "portvakt.jwks.stale-max-age"),
          Map.entry("acrRanking", "portvakt.acr-ranking"),
          Map.entry("clock", "portvakt clock"));

  private PortvaktPropertiesMapper() {}

  static PortvaktConfig config(PortvaktProperties properties, Clock clock) {
    List<String> issues = new ArrayList<>();
    ClientAuth clientAuth = null;
    try {
      clientAuth = clientAuth(properties);
    } catch (PortvaktConfigException invalid) {
      invalid.issues().forEach(issue -> issues.add(rename(issue)));
    }
    if (clientAuth == null) {
      if (properties.getLogin().isEnabled()) issues.add("portvakt.client-secret (or private-jwk): required for the login");
      if (properties.getClientCredentials().isEnabled()) {
        issues.add("portvakt.client-secret (or private-jwk): required for client credentials");
      }
    }
    if (properties.getLogin().isEnabled()) issues.addAll(loginIssues(properties));
    PortvaktConfig config = null;
    try {
      config =
          PortvaktConfig.builder()
              .issuer(properties.getIssuer())
              .clientId(properties.getClientId())
              .clientAuth(clientAuth)
              .scopes(properties.getScopes())
              .clockSkew(properties.getClockSkew())
              .httpTimeout(properties.getHttpTimeout())
              .discoveryCacheTtl(properties.getDiscoveryCache())
              .failureCacheTtl(properties.getFailureCache())
              .jwksCacheMaxAge(properties.getJwks().getCacheMaxAge())
              .jwksCooldown(properties.getJwks().getCooldown())
              .jwksStaleMaxAge(properties.getJwks().getStaleMaxAge())
              .acrRanking(properties.getAcrRanking() == null ? null : AcrRanking.of(properties.getAcrRanking()))
              .allowInsecureRequests(properties.isAllowInsecureRequests())
              .clock(clock)
              .build();
    } catch (PortvaktConfigException invalid) {
      invalid.issues().forEach(issue -> issues.add(rename(issue)));
    }
    if (!issues.isEmpty()) throw new PortvaktConfigException(issues);
    return config;
  }

  private static ClientAuth clientAuth(PortvaktProperties properties) {
    return switch (properties.getClientAuthMethod()) {
      case PRIVATE_KEY_JWT -> {
        if (properties.getPrivateJwk() == null || properties.getPrivateJwk().isBlank()) {
          throw new PortvaktConfigException(List.of("clientAuth.privateJwk: required for private_key_jwt"));
        }
        yield ClientAuth.privateKeyJwt(properties.getPrivateJwk());
      }
      case CLIENT_SECRET_POST ->
          properties.getClientSecret() == null ? null : ClientAuth.clientSecretPost(properties.getClientSecret());
      case CLIENT_SECRET_BASIC ->
          properties.getClientSecret() == null ? null : ClientAuth.clientSecretBasic(properties.getClientSecret());
    };
  }

  private static List<String> loginIssues(PortvaktProperties properties) {
    PortvaktProperties.Login login = properties.getLogin();
    List<String> issues = new ArrayList<>();
    String base = login.getBasePath();
    if (base == null || !base.matches("^(/[A-Za-z0-9._~-]+)+$")) {
      issues.add("portvakt.login.base-path: must be a path such as /auth, without a trailing slash");
      base = "/auth";
    }
    String redirect = login.getRedirectUri();
    if (redirect != null) {
      if (!redirect.startsWith("{baseUrl}") && !redirect.matches("^https?://[^/?#]+(/[^?#]*)?$")) {
        issues.add("portvakt.login.redirect-uri: must be an absolute URL or start with {baseUrl}");
      } else if (!redirect.endsWith(base + "/callback")) {
        issues.add("portvakt.login.redirect-uri: must point at the login callback (" + base + "/callback)");
      }
    }
    String postLogout = login.getPostLogoutRedirectUri();
    if (postLogout != null && !postLogout.startsWith("{baseUrl}") && !postLogout.matches("^https?://[^/?#]+(/[^#]*)?$")) {
      issues.add("portvakt.login.post-logout-redirect-uri: must be an absolute URL or start with {baseUrl}");
    }
    if (HttpRequests.safeReturnTo(login.getDefaultReturnTo()) == null) {
      issues.add("portvakt.login.default-return-to: must be a same-origin path");
    }
    range(issues, "portvakt.login.idle-timeout", login.getIdleTimeout(), Duration.ofSeconds(60), Duration.ofDays(7));
    range(issues, "portvakt.login.max-age", login.getMaxAge(), Duration.ofSeconds(60), Duration.ofDays(30));
    range(issues, "portvakt.login.outage-grace", login.getOutageGrace(), Duration.ZERO, Duration.ofDays(7));
    return issues;
  }

  static PortvaktLoginSettings loginSettings(PortvaktProperties properties) {
    PortvaktProperties.Login login = properties.getLogin();
    String base = login.getBasePath();
    return new PortvaktLoginSettings(
        base,
        login.getRedirectUri() != null ? login.getRedirectUri() : "{baseUrl}" + base + "/callback",
        login.getPostLogoutRedirectUri() != null ? login.getPostLogoutRedirectUri() : "{baseUrl}/",
        login.getDefaultReturnTo(),
        login.getIdleTimeout(),
        login.getMaxAge(),
        login.getOutageGrace(),
        login.getPublicPaths() == null ? List.of() : login.getPublicPaths());
  }

  static AccessTokenRequirements resourceDefaults(PortvaktProperties properties) {
    PortvaktProperties.ResourceServer server = properties.getResourceServer();
    String audience = server.getAudience() != null ? server.getAudience() : properties.getClientId();
    return AccessTokenRequirements.forAudience(audience)
        .allowService(server.isAllowService())
        .allowServices(server.getAllowedServices().toArray(String[]::new))
        .allowRepresentation(server.isAllowRepresentation())
        .build();
  }

  static List<String> resourcePaths(PortvaktProperties properties) {
    List<String> paths = properties.getResourceServer().getPaths();
    if (paths != null && !paths.isEmpty()) return List.copyOf(paths);
    return properties.getLogin().isEnabled() ? List.of("/api/**") : List.of("/**");
  }

  private static String rename(String issue) {
    int colon = issue.indexOf(':');
    if (colon < 0) return issue;
    String name = PROPERTY_NAMES.get(issue.substring(0, colon));
    return name == null ? "portvakt " + issue : name + issue.substring(colon);
  }

  private static void range(List<String> issues, String name, Duration value, Duration min, Duration max) {
    if (value == null || value.compareTo(min) < 0 || value.compareTo(max) > 0) {
      issues.add(name + ": must be between " + min + " and " + max);
    }
  }
}
