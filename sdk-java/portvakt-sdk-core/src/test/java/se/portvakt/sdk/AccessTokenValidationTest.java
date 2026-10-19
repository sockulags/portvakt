package se.portvakt.sdk;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** The TypeScript SDK's access token validation tests, against the Java core. */
class AccessTokenValidationTest {
  static final String PERSON = "3f2b8c4e-91d7-4a3e-8b6f-2d4c9e1a7b55";
  static final String LOA3 = AcrRanking.LOA3;
  static final String LOA4 = AcrRanking.LOA4;
  static final String LOA2 = AcrRanking.LOA2;

  static FakeOp op;

  @BeforeAll
  static void start() throws Exception {
    op = new FakeOp();
  }

  @AfterAll
  static void stop() {
    op.close();
  }

  /** Tokens are made at this clock's time, and the verifier uses it. */
  static volatile MutableClock clock = new MutableClock();

  @org.junit.jupiter.api.BeforeEach
  void freshClock() {
    clock = new MutableClock();
  }

  @AfterEach
  void reset() {
    op.down = false;
    op.serverError = null;
    op.jwksError = null;
    op.discoveryError = null;
    op.trickleJwks = false;
  }

  static long now() {
    return clock.instant().getEpochSecond();
  }

  /** Person access token claims as Portvakt issues them. */
  static Map<String, Object> person(Object... extra) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("iss", op.issuer);
    claims.put("aud", FakeOp.CLIENT_ID);
    claims.put("client_id", FakeOp.CLIENT_ID);
    claims.put("sub", PERSON);
    claims.put("tid", "fake");
    claims.put("idp", "0f1976f6-7f6c-4baf-a88c-2bc6f2e68ce7");
    claims.put("idp_kind", "employee");
    claims.put("acr", LOA3);
    claims.put("auth_time", now() - 10);
    claims.put("roles", List.of("handlaggare"));
    claims.put("attrs", Map.of("unit", "north"));
    claims.put("jti", "jti-1");
    claims.put("iat", now());
    claims.put("exp", now() + 300);
    return with(claims, extra);
  }

  static Map<String, Object> service(Object... extra) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("iss", op.issuer);
    claims.put("aud", FakeOp.CLIENT_ID);
    claims.put("client_id", "other-app");
    claims.put("sub", "other-app");
    claims.put("tid", "fake");
    claims.put("jti", "jti-2");
    claims.put("iat", now());
    claims.put("exp", now() + 300);
    return with(claims, extra);
  }

  /** Pairs of name, value; a {@code null} value removes the claim. */
  static Map<String, Object> with(Map<String, Object> claims, Object... extra) {
    for (int index = 0; index < extra.length; index += 2) {
      if (extra[index + 1] == null) claims.remove((String) extra[index]);
      else claims.put((String) extra[index], extra[index + 1]);
    }
    return claims;
  }

  static PortvaktClient client() {
    return PortvaktClient.create(op.config().clock(clock).build());
  }

  static PortvaktException refusal(PortvaktClient portvakt, String token) {
    return refusal(portvakt, token, FakeOp.CLIENT_ID);
  }

  static PortvaktException refusal(PortvaktClient portvakt, String token, String audience) {
    try {
      portvakt.verifier().verifyAccessToken(token, audience);
    } catch (PortvaktException error) {
      return error;
    }
    throw new AssertionError("expected the token to be refused");
  }

  @Test
  void acceptsAPersonTokenAndMapsThePrincipal() throws Exception {
    PortvaktClient portvakt = client();
    String token = op.sign(person("rep", Map.of("sub", "party-1", "type", "organisation", "name", "Bygg AB")));
    PortvaktPrincipal principal = portvakt.verifier().verifyAccessToken(token, FakeOp.CLIENT_ID);
    assertThat(principal.isService()).isFalse();
    assertThat(principal.sub()).isEqualTo(PERSON);
    assertThat(principal.tenant()).isEqualTo("fake");
    assertThat(principal.idp()).isEqualTo("0f1976f6-7f6c-4baf-a88c-2bc6f2e68ce7");
    assertThat(principal.idpKind()).isEqualTo(IdpKind.EMPLOYEE);
    assertThat(principal.acr()).isEqualTo(LOA3);
    assertThat(principal.roles()).containsExactly("handlaggare");
    assertThat(principal.attrs()).containsEntry("unit", "north");
    // Access tokens never carry profile data: a name inside rep is ignored.
    assertThat(principal.rep())
        .isEqualTo(new Representation("party-1", Representation.Type.ORGANISATION, null));
    assertThat(principal.clientId()).isEqualTo(FakeOp.CLIENT_ID);
    assertThat(principal.name()).isNull();
    assertThat(principal.toString()).doesNotContain("Bygg AB");
  }

  @Test
  void tellsServiceTokensFromPersonTokensByTheClaimsPortvaktIssues() throws Exception {
    PortvaktClient portvakt = client();
    PortvaktPrincipal principal =
        portvakt.verifier().verifyAccessToken(op.sign(service()), FakeOp.CLIENT_ID);
    assertThat(principal.isService()).isTrue();
    assertThat(principal.sub()).isEqualTo("other-app");
    assertThat(principal.clientId()).isEqualTo("other-app");
    assertThat(principal.tenant()).isEqualTo("fake");
    assertThat(principal.roles()).isEmpty();
    assertThat(principal.attrs()).isEmpty();
    assertThat(principal.acr()).isNull();

    // A token with login claims but sub = client_id, or a service token whose sub is not its
    // client, is neither.
    assertThat(refusal(portvakt, op.sign(person("sub", FakeOp.CLIENT_ID))).code()).isEqualTo("invalid_token");
    assertThat(refusal(portvakt, op.sign(service("sub", PERSON))).code()).isEqualTo("invalid_token");
    // A person token missing a login claim is refused.
    assertThat(refusal(portvakt, op.sign(person("auth_time", null))).code()).isEqualTo("invalid_token");
  }

  @Test
  void refusesMalformedHybridsOfPersonAndServiceTokens() throws Exception {
    PortvaktClient portvakt = client();
    List<Map<String, Object>> hybrids =
        List.of(
            // A service token with one login claim is judged as a person token, and fails.
            service("roles", List.of()),
            service("acr", LOA4),
            service("rep", Map.of("sub", "party-1", "type", "person")),
            // Person tokens must carry roles and attrs as Portvakt issues them.
            person("roles", null),
            person("attrs", null),
            person("roles", Map.of("a", "b")),
            person("attrs", List.of("x")),
            person("roles", List.of(1)),
            person("idp_kind", "robot"),
            person("auth_time", -1),
            person("auth_time", "yesterday"),
            person("idp", ""),
            person("tid", null),
            person("client_id", null),
            person("rep", Map.of("sub", "party-1", "type", "company")),
            person("rep", "party-1"),
            // Service tokens need a tenant and sub = client_id.
            service("tid", null),
            service("sub", "third-app"));
    for (Map<String, Object> claims : hybrids) {
      assertThat(refusal(portvakt, op.sign(claims)).code()).as(claims.toString()).isEqualTo("invalid_token");
    }
  }

  @Test
  void pinsIssExactlyATokenOfAnotherTenantSignedWithTheSharedKeysIsRefused() throws Exception {
    PortvaktClient portvakt = client();
    PortvaktException otherTenant = refusal(portvakt, op.sign(person("iss", op.baseUrl + "/t/other")));
    assertThat(otherTenant.code()).isEqualTo("invalid_token");
    assertThat(otherTenant.status()).isEqualTo(401);
    assertThat(refusal(portvakt, op.sign(person("iss", op.issuer + "/"))).code()).isEqualTo("invalid_token");
    assertThat(refusal(portvakt, op.sign(person("iss", op.issuer.toUpperCase()))).code()).isEqualTo("invalid_token");
  }

  @Test
  void refusesAWrongAudienceWrongTypExpiredNotYetValidOrFutureToken() throws Exception {
    PortvaktClient portvakt = client();
    String token = op.sign(person());
    assertThat(refusal(portvakt, token, "service-b").code()).isEqualTo("invalid_token");
    // An ID token (typ JWT or none) presented as an access token.
    assertThat(refusal(portvakt, op.sign(person(), op.signingKey(), JOSEObjectType.JWT)).code())
        .isEqualTo("invalid_token");
    assertThat(refusal(portvakt, op.sign(person(), op.signingKey(), null)).code()).isEqualTo("invalid_token");
    AccessTokenException expired =
        (AccessTokenException) refusal(portvakt, op.sign(person("exp", now() - 120, "iat", now() - 400)));
    assertThat(expired.code()).isEqualTo("invalid_token");
    assertThat(expired.description()).isEqualTo("The access token has expired");
    assertThat(refusal(portvakt, op.sign(person("nbf", now() + 600))).code()).isEqualTo("invalid_token");
    assertThat(refusal(portvakt, op.sign(person("iat", now() + 600))).code()).isEqualTo("invalid_token");
    // Within the clock skew (30 s) a just-expired token still passes.
    assertThat(portvakt.verifier().verifyAccessToken(op.sign(person("exp", now() - 5)), FakeOp.CLIENT_ID).sub())
        .isEqualTo(PERSON);
    // The media type form of the typ is accepted (RFC 9068).
    assertThat(
            portvakt.verifier()
                .verifyAccessToken(
                    op.sign(person(), op.signingKey(), new JOSEObjectType("application/at+jwt")),
                    FakeOp.CLIENT_ID)
                .sub())
        .isEqualTo(PERSON);
  }

  @Test
  void refusesAlgNoneHs256Rs256AndASignatureByAnUnpublishedKey() throws Exception {
    PortvaktClient portvakt = client();
    String payload =
        Base64URL.encode(JSONObjectUtils.toJSONString(person()).getBytes(StandardCharsets.UTF_8)).toString();
    String noneHeader =
        Base64URL.encode("{\"alg\":\"none\",\"typ\":\"at+jwt\",\"kid\":\"key-1\"}".getBytes(StandardCharsets.UTF_8))
            .toString();
    assertThat(refusal(portvakt, noneHeader + "." + payload + ".").code()).isEqualTo("invalid_token");

    SignedJWT hmac =
        new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.HS256).type(new JOSEObjectType("at+jwt")).keyID("key-1").build(),
            JWTClaimsSet.parse(person()));
    hmac.sign(new MACSigner("a-shared-secret-that-is-long-enough-for-hs256".getBytes(StandardCharsets.UTF_8)));
    assertThat(refusal(portvakt, hmac.serialize()).code()).isEqualTo("invalid_token");

    RSAKey rsa = new RSAKeyGenerator(2048).keyID("key-1").generate();
    SignedJWT rs256 =
        new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256).type(new JOSEObjectType("at+jwt")).keyID("key-1").build(),
            JWTClaimsSet.parse(person()));
    rs256.sign(new RSASSASigner(rsa));
    assertThat(refusal(portvakt, rs256.serialize()).code()).isEqualTo("invalid_token");

    // The published kid, but signed by another key.
    com.nimbusds.jose.jwk.ECKey foreign =
        new com.nimbusds.jose.jwk.ECKey.Builder(FakeOp.foreignKey()).keyID("key-1").build();
    assertThat(refusal(portvakt, op.sign(person(), foreign, new JOSEObjectType("at+jwt"))).code())
        .isEqualTo("invalid_token");
    // Not a JWT at all.
    assertThat(refusal(portvakt, "abc.def.ghi").code()).isEqualTo("invalid_token");
    assertThat(refusal(portvakt, "a.b").code()).isEqualTo("invalid_token");
  }

  @Test
  void refetchesTheJwksForAnUnknownKidRateLimitedAndKeepsStaleKeysOnError() throws Exception {
    PortvaktClient portvakt = client();
    portvakt.verifier().verifyAccessToken(op.sign(person()), FakeOp.CLIENT_ID);
    int baseline = op.jwksRequests.get();
    clock.advance(Duration.ofSeconds(31));

    // A rotated-in key: one refetch finds it.
    String kid = op.addKey();
    com.nimbusds.jose.jwk.ECKey rotated = op.keys.get(op.keys.size() - 1);
    assertThat(rotated.getKeyID()).isEqualTo(kid);
    assertThat(
            portvakt.verifier()
                .verifyAccessToken(op.sign(person(), rotated, new JOSEObjectType("at+jwt")), FakeOp.CLIENT_ID)
                .sub())
        .isEqualTo(PERSON);
    assertThat(op.jwksRequests.get()).isEqualTo(baseline + 1);

    // Unknown kids within the cooldown do not refetch.
    com.nimbusds.jose.jwk.ECKey foreign = FakeOp.foreignKey();
    for (int attempt = 0; attempt < 5; attempt++) {
      String token = op.sign(person(), foreign, new JOSEObjectType("at+jwt"));
      assertThat(refusal(portvakt, token).code()).isEqualTo("invalid_token");
    }
    assertThat(op.jwksRequests.get()).isEqualTo(baseline + 1);

    // After the cooldown one more refetch is allowed.
    clock.advance(Duration.ofSeconds(31));
    assertThat(refusal(portvakt, op.sign(person(), foreign, new JOSEObjectType("at+jwt"))).code())
        .isEqualTo("invalid_token");
    assertThat(op.jwksRequests.get()).isEqualTo(baseline + 2);

    // Portvakt down: known keys keep working (stale-if-error), even past the cache age.
    op.down = true;
    clock.advance(Duration.ofSeconds(700));
    assertThat(portvakt.verifier().verifyAccessToken(op.sign(person()), FakeOp.CLIENT_ID).sub()).isEqualTo(PERSON);
  }

  @Test
  void answersUnavailableWhenTheKeysWereNeverFetchedAndPortvaktIsDown() throws Exception {
    PortvaktClient portvakt = client();
    op.down = true;
    PortvaktException error = refusal(portvakt, op.sign(person()));
    assertThat(error).isInstanceOf(PortvaktUnavailableException.class);
    assertThat(error.code()).isEqualTo("portvakt_unavailable");
    assertThat(error.status()).isEqualTo(503);
  }

  @Test
  void stopsTrustingCachedKeysPastCacheMaxAgePlusStaleMaxAgeAlsoWithinTheCooldown() throws Exception {
    PortvaktClient portvakt = client();
    portvakt.verifier().verifyAccessToken(op.sign(person()), FakeOp.CLIENT_ID);
    // A day (cache age plus stale limit) is fine while Portvakt answers nothing...
    op.down = true;
    clock.advance(Duration.ofSeconds(80_000));
    assertThat(portvakt.verifier().verifyAccessToken(op.sign(person()), FakeOp.CLIENT_ID).sub()).isEqualTo(PERSON);
    // ...a month is not: the refetch fails, and the next request (within the cooldown, so no
    // refetch) must not fall back to the month-old keys either.
    clock.advance(Duration.ofDays(30));
    for (int attempt = 0; attempt < 2; attempt++) {
      String token = op.sign(person());
      assertThat(refusal(portvakt, token).code()).isEqualTo("portvakt_unavailable");
    }
  }

  @Test
  void treatsA5xxJwksOrDiscoveryAnswerAsUnavailable() throws Exception {
    PortvaktClient portvakt = client();
    op.serverError = 503;
    PortvaktException error = refusal(portvakt, op.sign(person()));
    assertThat(error.code()).isEqualTo("portvakt_unavailable");
    assertThat(error.status()).isEqualTo(503);
  }

  @Test
  void treatsA5xxFromTheJwksAloneOrFromDiscoveryAloneAsUnavailable() throws Exception {
    op.jwksError = 503;
    PortvaktException jwks = refusal(client(), op.sign(person()));
    assertThat(jwks).isInstanceOf(PortvaktUnavailableException.class);
    assertThat(jwks.status()).isEqualTo(503);
    op.jwksError = null;
    op.discoveryError = 502;
    PortvaktException discovery = refusal(client(), op.sign(person()));
    assertThat(discovery).isInstanceOf(PortvaktUnavailableException.class);
    assertThat(discovery.status()).isEqualTo(503);
  }

  @Test
  void boundsTheWholeRequestNotOnlyTheHeaders() throws Exception {
    PortvaktClient portvakt = PortvaktClient.create(op.config().clock(clock).httpTimeout(Duration.ofSeconds(1)).build());
    portvakt.discovery().get();
    op.trickleJwks = true;
    long started = System.nanoTime();
    PortvaktException error = refusal(portvakt, op.sign(person()));
    long elapsedMs = (System.nanoTime() - started) / 1_000_000;
    assertThat(error).isInstanceOf(PortvaktUnavailableException.class);
    assertThat(elapsedMs).isLessThan(5_000);
  }

  @Test
  void doesNotHitPortvaktForEveryRequestWhileNothingIsCachedNegativeCache() throws Exception {
    for (String mode : List.of("down", "5xx")) {
      PortvaktClient portvakt = client();
      if (mode.equals("down")) op.down = true;
      else op.serverError = 502;
      int before = op.failedRequests.get();
      String token = op.sign(person());
      for (int attempt = 0; attempt < 20; attempt++) {
        assertThat(refusal(portvakt, token).code()).isEqualTo("portvakt_unavailable");
      }
      // One discovery attempt; the rest are answered from the failure cache.
      assertThat(op.failedRequests.get() - before).isLessThanOrEqualTo(2);
      op.down = false;
      op.serverError = null;
    }
  }

  @Test
  void sharesOneJwksFetchBetweenConcurrentCallers() throws Exception {
    PortvaktClient portvakt = client();
    int before = op.jwksRequests.get();
    String token = op.sign(person());
    List<Thread> threads = new java.util.ArrayList<>();
    java.util.concurrent.atomic.AtomicInteger ok = new java.util.concurrent.atomic.AtomicInteger();
    for (int index = 0; index < 16; index++) {
      threads.add(
          Thread.ofVirtual()
              .start(
                  () -> {
                    portvakt.verifier().verifyAccessToken(token, FakeOp.CLIENT_ID);
                    ok.incrementAndGet();
                  }));
    }
    for (Thread thread : threads) thread.join();
    assertThat(ok.get()).isEqualTo(16);
    assertThat(op.jwksRequests.get() - before).isEqualTo(1);
  }

  @Nested
  class Authorization {
    final PortvaktClient portvakt = client();

    PortvaktPrincipal verified(Map<String, Object> claims) throws Exception {
      return portvakt.verifier().verifyAccessToken(op.sign(claims), FakeOp.CLIENT_ID);
    }

    AccessTokenException denial(PortvaktPrincipal principal, AccessTokenRequirements requirements) {
      try {
        portvakt.verifier().authorize(principal, requirements);
      } catch (AccessTokenException error) {
        return error;
      }
      throw new AssertionError("expected a denial");
    }

    @Test
    void checksRolesAnyRoleAndAcr() throws Exception {
      PortvaktPrincipal principal = verified(person());
      AccessTokenException roles =
          denial(principal, AccessTokenRequirements.forAudience(FakeOp.CLIENT_ID).roles("handlaggare", "admin").build());
      assertThat(roles.status()).isEqualTo(403);
      assertThat(roles.error()).isEqualTo(BearerError.INSUFFICIENT_SCOPE);
      assertThat(roles.reason()).isEqualTo("missing_role");
      assertThat(roles.wwwAuthenticate()).contains("error=\"insufficient_scope\"");
      portvakt.verifier()
          .authorize(principal, AccessTokenRequirements.forAudience(FakeOp.CLIENT_ID).anyRole("admin", "handlaggare").build());

      AccessTokenException loa4 =
          denial(principal, AccessTokenRequirements.forAudience(FakeOp.CLIENT_ID).acr(LOA4).build());
      assertThat(loa4.status()).isEqualTo(401);
      assertThat(loa4.wwwAuthenticate())
          .contains("error=\"insufficient_user_authentication\"")
          .contains("acr_values=\"" + LOA4 + "\"");
      assertThat(loa4.body()).containsEntry("acr_values", LOA4);
      portvakt.verifier()
          .authorize(verified(person("acr", LOA4)), AccessTokenRequirements.forAudience(FakeOp.CLIENT_ID).acr(LOA4).build());
    }

    @Test
    void refusesServiceTokensUnlessAllowedAndRepresentationWhenRefused() throws Exception {
      PortvaktPrincipal caller = verified(service());
      AccessTokenRequirements plain = AccessTokenRequirements.forAudience(FakeOp.CLIENT_ID).build();
      assertThat(denial(caller, plain).reason()).isEqualTo("service_not_allowed");
      portvakt.verifier()
          .authorize(caller, AccessTokenRequirements.forAudience(FakeOp.CLIENT_ID).allowServices("other-app").build());
      // Role requirements apply to persons only.
      portvakt.verifier()
          .authorize(
              caller,
              AccessTokenRequirements.forAudience(FakeOp.CLIENT_ID).allowService(true).roles("admin").acr(LOA4).build());
      PortvaktPrincipal stranger = verified(service("sub", "third-app", "client_id", "third-app"));
      assertThat(
              denial(stranger, AccessTokenRequirements.forAudience(FakeOp.CLIENT_ID).allowServices("other-app").build())
                  .reason())
          .isEqualTo("service_not_allowed");

      PortvaktPrincipal acting = verified(person("rep", Map.of("sub", "party-1", "type", "person")));
      portvakt.verifier().authorize(acting, plain);
      assertThat(
              denial(acting, AccessTokenRequirements.forAudience(FakeOp.CLIENT_ID).allowRepresentation(false).build())
                  .reason())
          .isEqualTo("representation_not_allowed");
    }
  }

  @Nested
  class BearerHeader {
    @Test
    void readsExactlyOneBearerToken() {
      assertThat(BearerTokens.fromAuthorizationHeader(null)).isNull();
      assertThat(BearerTokens.fromAuthorizationHeader("Bearer abc.def.ghi")).isEqualTo("abc.def.ghi");
      assertThat(BearerTokens.fromAuthorizationHeader("bearer abc")).isEqualTo("abc");
      AccessTokenException basic =
          catchAccessTokenError(() -> BearerTokens.fromAuthorizationHeader("Basic dXNlcjpwYXNz"));
      assertThat(basic.status()).isEqualTo(400);
      assertThat(basic.wwwAuthenticate()).contains("error=\"invalid_request\"");
      assertThat(catchAccessTokenError(() -> BearerTokens.fromAuthorizationHeader("Bearer a b")).status())
          .isEqualTo(400);
      assertThat(catchAccessTokenError(() -> BearerTokens.fromAuthorizationHeader("Bearer ab%cd")).status())
          .isEqualTo(401);
      assertThat(AccessTokenException.missingToken().wwwAuthenticate()).isEqualTo("Bearer realm=\"portvakt\"");
      assertThat(AccessTokenException.invalidToken().wwwAuthenticate())
          .isEqualTo(
              "Bearer realm=\"portvakt\", error=\"invalid_token\", error_description=\"The access token is invalid\"");
    }

    private AccessTokenException catchAccessTokenError(Runnable runnable) {
      try {
        runnable.run();
      } catch (AccessTokenException error) {
        return error;
      }
      throw new AssertionError("expected an error");
    }
  }

  @Test
  void ranksAcrWithPortvaktsSemantics() {
    assertThat(AcrRanking.DEFAULT.atLeast(LOA4, LOA3)).isTrue();
    assertThat(AcrRanking.DEFAULT.atLeast(LOA3, LOA4)).isFalse();
    assertThat(AcrRanking.DEFAULT.atLeast("urn:portvakt:acr:employee", "urn:portvakt:acr:employee")).isTrue();
    assertThat(AcrRanking.DEFAULT.atLeast("urn:portvakt:acr:employee", LOA2)).isFalse();
    assertThat(AcrRanking.DEFAULT.atLeast(LOA4, "urn:other")).isFalse();
    assertThat(AcrRanking.DEFAULT.atLeast(null, LOA2)).isFalse();
  }

  @Test
  void refusesTheVerifierWithoutAToken() {
    PortvaktClient portvakt = client();
    assertThatThrownBy(() -> portvakt.verifier().verifyAccessToken(null, FakeOp.CLIENT_ID))
        .isInstanceOf(AccessTokenException.class);
  }
}
