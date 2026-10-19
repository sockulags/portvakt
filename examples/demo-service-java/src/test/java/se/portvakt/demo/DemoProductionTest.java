package se.portvakt.demo;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import se.portvakt.sdk.ClientAuth;
import se.portvakt.sdk.PortvaktConfig;

/** What DEMO_PRODUCTION=true refuses: development values, http, and an insecure session cookie. */
class DemoProductionTest {
  static PortvaktConfig.Builder config() {
    return PortvaktConfig.builder()
        .issuer("https://login.example.org/t/demo")
        .clientId("service-c")
        .clientAuth(ClientAuth.clientSecretBasic("a-production-client-secret-0123456789"));
  }

  static MockEnvironment cookie(String secure, String sameSite) {
    MockEnvironment environment = new MockEnvironment();
    if (secure != null) environment.setProperty("server.servlet.session.cookie.secure", secure);
    if (sameSite != null) environment.setProperty("server.servlet.session.cookie.same-site", sameSite);
    return environment;
  }

  @Test
  void refusesAnInsecureCookieAndTransportInProduction() {
    assertThat(DemoSecurityHeaders.productionIssues(config().build(), cookie("true", "lax"))).isEmpty();
    assertThat(DemoSecurityHeaders.productionIssues(config().build(), cookie("false", "lax")))
        .containsExactly("the session cookie must be Secure (server.servlet.session.cookie.secure)");
    assertThat(DemoSecurityHeaders.productionIssues(config().build(), cookie(null, "lax")))
        .containsExactly("the session cookie must be Secure (server.servlet.session.cookie.secure)");
    assertThat(DemoSecurityHeaders.productionIssues(config().build(), cookie("true", null)))
        .containsExactly("the session cookie needs SameSite lax or strict");
    assertThat(DemoSecurityHeaders.productionIssues(config().build(), cookie("true", "none")))
        .containsExactly("the session cookie needs SameSite lax or strict");
    PortvaktConfig local =
        config()
            .issuer("http://localhost:3000/t/demo")
            .allowInsecureRequests(true)
            .clientAuth(ClientAuth.clientSecretBasic(DemoProperties.DEV_CLIENT_SECRET))
            .build();
    assertThat(DemoSecurityHeaders.productionIssues(local, cookie("true", "lax")))
        .containsExactly(
            "the issuer must be https",
            "portvakt.allow-insecure-requests must be false",
            "the development client secret is refused");
  }

  @Test
  void defaultsToASecureCookieAndHttpsUnlessTheLocalProfileIsActive() throws Exception {
    org.springframework.boot.env.YamlPropertySourceLoader yaml = new org.springframework.boot.env.YamlPropertySourceLoader();
    var main = yaml.load("main", new org.springframework.core.io.ClassPathResource("application.yml")).get(0);
    var local = yaml.load("local", new org.springframework.core.io.ClassPathResource("application-local.yml")).get(0);
    assertThat(String.valueOf(main.getProperty("server.servlet.session.cookie.secure"))).isEqualTo("${COOKIE_SECURE:true}");
    assertThat(String.valueOf(main.getProperty("portvakt.allow-insecure-requests"))).isEqualTo("${ALLOW_INSECURE_REQUESTS:false}");
    assertThat(String.valueOf(local.getProperty("server.servlet.session.cookie.secure"))).isEqualTo("${COOKIE_SECURE:false}");
    assertThat(String.valueOf(local.getProperty("portvakt.allow-insecure-requests"))).isEqualTo("${ALLOW_INSECURE_REQUESTS:true}");
  }
}
