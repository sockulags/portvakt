package se.portvakt.sdk;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;

class ConfigTest {
  static final String SECRET = "a-client-secret-0123456789";

  static PortvaktConfig.Builder valid() {
    return PortvaktConfig.builder()
        .issuer("https://login.example.org/t/kommunen")
        .clientId("case-service")
        .clientAuth(ClientAuth.clientSecretBasic(SECRET));
  }

  static List<String> issues(PortvaktConfig.Builder builder) {
    try {
      builder.build();
    } catch (PortvaktConfigException error) {
      assertThat(error.getMessage()).doesNotContain(SECRET).doesNotContain("short");
      return error.issues();
    }
    throw new AssertionError("expected a configuration error");
  }

  @Test
  void appliesTheDefaults() {
    PortvaktConfig config = valid().build();
    assertThat(config.scopes()).containsExactly("openid", "profile", "email");
    assertThat(config.clockSkew()).isEqualTo(Duration.ofSeconds(30));
    assertThat(config.httpTimeout()).isEqualTo(Duration.ofSeconds(10));
    assertThat(config.discoveryCacheTtl()).isEqualTo(Duration.ofHours(1));
    assertThat(config.failureCacheTtl()).isEqualTo(Duration.ofSeconds(5));
    assertThat(config.jwksCacheMaxAge()).isEqualTo(Duration.ofMinutes(5));
    assertThat(config.jwksCooldown()).isEqualTo(Duration.ofSeconds(30));
    assertThat(config.jwksStaleMaxAge()).isEqualTo(Duration.ofDays(1));
    assertThat(config.acrRanking()).isEqualTo(AcrRanking.DEFAULT);
    assertThat(config.toString()).doesNotContain(SECRET);
  }

  @Test
  void refusesAnInvalidIssuer() {
    assertThat(issues(valid().issuer(null))).containsExactly("issuer: required");
    assertThat(issues(valid().issuer("http://login.example.org/t/kommunen")))
        .anyMatch(issue -> issue.startsWith("issuer: must be https"));
    assertThat(valid().issuer("http://localhost:3000/t/demo").allowInsecureRequests(true).build().issuer())
        .isEqualTo("http://localhost:3000/t/demo");
    assertThat(issues(valid().issuer("https://login.example.org/t/kommunen/")))
        .anyMatch(issue -> issue.contains("trailing slash"));
    assertThat(issues(valid().issuer("https://login.example.org/t/kommunen?x=1")))
        .anyMatch(issue -> issue.contains("trailing slash or query"));
    assertThat(issues(valid().issuer("https://user:pw@login.example.org/t/k")))
        .anyMatch(issue -> issue.contains("credentials"));
    assertThat(issues(valid().issuer("/t/kommunen"))).containsExactly("issuer: must be an absolute URL");
  }

  @Test
  void listsEveryProblemWithoutEchoingValues() {
    List<String> issues =
        issues(
            PortvaktConfig.builder()
                .issuer("https://login.example.org/t/k")
                .clientAuth(ClientAuth.clientSecretBasic("short"))
                .scopes(List.of("profile"))
                .clockSkew(Duration.ofMinutes(10))
                .httpTimeout(Duration.ZERO));
    assertThat(issues)
        .contains(
            "clientId: required, 1 to 255 characters",
            "clientAuth.clientSecret: at least 16 characters",
            "scopes: must include openid")
        .anyMatch(issue -> issue.startsWith("clockSkew:"))
        .anyMatch(issue -> issue.startsWith("httpTimeout:"));
  }

  @Test
  void acceptsAPrivateKeyJwtOnlyWithAPrivateKeyAndKid() throws Exception {
    var key = new ECKeyGenerator(Curve.P_256).keyID("k1").generate();
    assertThat(valid().clientAuth(ClientAuth.privateKeyJwt(key)).build().clientAuth().method())
        .isEqualTo("private_key_jwt");
    assertThat(issues(valid().clientAuth(ClientAuth.privateKeyJwt(key.toPublicJWK()))))
        .containsExactly("clientAuth.privateJwk: must be a private key");
    var noKid = new ECKeyGenerator(Curve.P_256).generate();
    assertThat(issues(valid().clientAuth(ClientAuth.privateKeyJwt(noKid))))
        .containsExactly("clientAuth.privateJwk: kid is required");
    assertThatThrownBy(() -> ClientAuth.privateKeyJwt("{not json"))
        .isInstanceOf(PortvaktConfigException.class);
  }

  @Test
  void allowsAResourceServerWithoutClientAuthentication() {
    assertThat(valid().clientAuth(null).build().clientAuth()).isNull();
  }
}
