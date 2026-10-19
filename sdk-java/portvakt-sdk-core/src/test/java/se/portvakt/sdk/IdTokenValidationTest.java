package se.portvakt.sdk;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JOSEObjectType;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class IdTokenValidationTest {
  static FakeOp op;

  @BeforeAll
  static void start() throws Exception {
    op = new FakeOp();
  }

  @AfterAll
  static void stop() {
    op.close();
  }

  static Map<String, Object> idToken(Object... extra) {
    long now = Instant.now().getEpochSecond();
    Map<String, Object> claims = new HashMap<>();
    claims.put("iss", op.issuer);
    claims.put("aud", FakeOp.CLIENT_ID);
    claims.put("sub", "8a41c2d0-5e3b-4f7a-9c18-6b2e0d4f3a91");
    claims.put("tid", "fake");
    claims.put("idp", "5d0c7e12-3a4b-4c8d-9e6f-1a2b3c4d5e6f");
    claims.put("idp_kind", "citizen");
    claims.put("acr", AcrRanking.LOA3);
    claims.put("amr", List.of("mfa"));
    claims.put("auth_time", now - 5);
    claims.put("session_exp", now + 3600);
    claims.put("roles", List.of());
    claims.put("attrs", Map.of());
    claims.put("name", "Sven Medborgare");
    claims.put("pin", "191212121212");
    claims.put("rep", Map.of("sub", "e7c1a9b2-4d3f-4a8e-b6c5-0f9d2e1a3b47", "type", "organisation", "name", "Bygg AB"));
    claims.put("nonce", "n-1");
    claims.put("iat", now);
    claims.put("exp", now + 300);
    return AccessTokenValidationTest.with(claims, extra);
  }

  final PortvaktClient portvakt = PortvaktClient.create(op.config().build());

  String sign(Map<String, Object> claims) throws Exception {
    return op.sign(claims, op.signingKey(), JOSEObjectType.JWT);
  }

  @Test
  void mapsAnIdTokenWithProfileFieldsAndSessionExp() throws Exception {
    Map<String, Object> claims = idToken();
    PortvaktTokenVerifier.VerifiedIdToken verified = portvakt.verifier().verifyIdToken(sign(claims));
    PortvaktPrincipal principal = verified.principal();
    assertThat(principal.idpKind()).isEqualTo(IdpKind.CITIZEN);
    assertThat(principal.name()).isEqualTo("Sven Medborgare");
    assertThat(principal.pin()).isEqualTo("191212121212");
    assertThat(principal.rep().name()).isEqualTo("Bygg AB");
    assertThat(principal.clientId()).isEqualTo(FakeOp.CLIENT_ID);
    assertThat(verified.sessionExp().getEpochSecond()).isEqualTo(claims.get("session_exp"));
    assertThat(principal.toString()).doesNotContain("Sven").doesNotContain("191212121212");
  }

  @Test
  void dropsNameAndEmailForAProtectedIdentity() throws Exception {
    PortvaktPrincipal principal =
        portvakt.verifier()
            .verifyIdToken(sign(idToken("protected_identity", true, "email", "x@example.org")))
            .principal();
    assertThat(principal.protectedIdentity()).isTrue();
    assertThat(principal.name()).isNull();
    assertThat(principal.email()).isNull();
  }

  @Test
  void refusesAccessTokensWrongAudienceOtherTenantsAndContractViolations() throws Exception {
    PortvaktTokenVerifier verifier = portvakt.verifier();
    // An access token is not an ID token.
    assertThatThrownBy(() -> verifier.verifyIdToken(op.sign(idToken())))
        .isInstanceOf(AccessTokenException.class);
    assertThatThrownBy(() -> verifier.verifyIdToken(sign(idToken("aud", "service-b"))))
        .isInstanceOf(AccessTokenException.class);
    assertThatThrownBy(() -> verifier.verifyIdToken(sign(idToken("aud", List.of(FakeOp.CLIENT_ID, "x")))))
        .isInstanceOf(AccessTokenException.class);
    verifier.verifyIdToken(sign(idToken("aud", List.of(FakeOp.CLIENT_ID, "x"), "azp", FakeOp.CLIENT_ID)));
    assertThatThrownBy(() -> verifier.verifyIdToken(sign(idToken("iss", op.baseUrl + "/t/other"))))
        .isInstanceOf(AccessTokenException.class);
    for (Object[] broken :
        List.of(
            new Object[] {"protected_identity", false},
            new Object[] {"session_exp", 0},
            new Object[] {"name", null, "rep", Map.of("sub", "x", "type", "robot")},
            new Object[] {"org_affiliation", "a@b"},
            new Object[] {"pin", 191212121212L},
            new Object[] {"idp_kind", null})) {
      assertThatThrownBy(() -> verifier.verifyIdToken(sign(idToken(broken))))
          .as(java.util.Arrays.toString(broken))
          .isInstanceOf(AccessTokenException.class);
    }
  }
}
