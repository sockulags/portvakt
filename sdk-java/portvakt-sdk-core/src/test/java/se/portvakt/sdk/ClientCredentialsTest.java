package se.portvakt.sdk;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class ClientCredentialsTest {
  static FakeOp op;

  @BeforeAll
  static void start() throws Exception {
    op = new FakeOp();
  }

  @AfterAll
  static void stop() {
    op.close();
  }

  @AfterEach
  void reset() {
    op.down = false;
    op.serverError = null;
    op.tokenError = null;
    op.tokenLifetime = 300;
  }

  @Test
  void requestsTheResourceIndicatorAndCachesUntilShortlyBeforeExpiry() {
    MutableClock clock = new MutableClock();
    PortvaktClient portvakt = PortvaktClient.create(op.config().clock(clock).build());
    ServiceTokenSource tokens = portvakt.clientCredentials().forAudience("archive-service");
    int before = op.tokenRequests.get();
    String first = tokens.getToken();
    assertThat(tokens.getToken()).isEqualTo(first);
    assertThat(op.tokenRequests.get() - before).isEqualTo(1);
    var form = op.tokenForms.get(op.tokenForms.size() - 1);
    assertThat(form)
        .containsEntry("grant_type", "client_credentials")
        .containsEntry("resource", "urn:portvakt:app:archive-service")
        .doesNotContainKey("client_secret");
    String basic = op.tokenAuthorizations.get(op.tokenAuthorizations.size() - 1);
    assertThat(new String(Base64.getDecoder().decode(basic.substring("Basic ".length()))))
        .isEqualTo(FakeOp.CLIENT_ID + ":" + FakeOp.CLIENT_SECRET);

    // 300 s lifetime: fetched again 30 s before the end.
    clock.advance(Duration.ofSeconds(265));
    assertThat(tokens.getToken()).isEqualTo(first);
    clock.advance(Duration.ofSeconds(10));
    assertThat(tokens.getToken()).isNotEqualTo(first);
    // The same source is shared per audience.
    assertThat(portvakt.clientCredentials().forAudience("archive-service")).isSameAs(tokens);
  }

  @Test
  void computesTheRefreshMargin() {
    assertThat(ClientCredentialsTokenProvider.refreshMarginSeconds(300)).isEqualTo(30);
    assertThat(ClientCredentialsTokenProvider.refreshMarginSeconds(3600)).isEqualTo(360);
    assertThat(ClientCredentialsTokenProvider.refreshMarginSeconds(40)).isEqualTo(20);
  }

  @Test
  void fetchesOnceForConcurrentCallers() throws Exception {
    PortvaktClient portvakt = PortvaktClient.create(op.config().build());
    ServiceTokenSource tokens = portvakt.clientCredentials().forAudience("concurrent");
    int before = op.tokenRequests.get();
    List<Thread> threads = new ArrayList<>();
    for (int index = 0; index < 10; index++) threads.add(Thread.ofVirtual().start(tokens::getToken));
    for (Thread thread : threads) thread.join();
    assertThat(op.tokenRequests.get() - before).isEqualTo(1);
  }

  @Test
  void treatsNetworkErrorsAnd5xxAsUnavailableAndRefusalsAsErrors() {
    PortvaktClient portvakt = PortvaktClient.create(op.config().build());
    ServiceTokenSource tokens = portvakt.clientCredentials().forAudience("archive-service");
    tokens.getToken(); // discovery cached
    tokens.clear();
    op.down = true;
    assertThatThrownBy(tokens::getToken).isInstanceOf(PortvaktUnavailableException.class);
    op.down = false;
    op.serverError = 502;
    assertThatThrownBy(tokens::getToken).isInstanceOf(PortvaktUnavailableException.class);
    op.serverError = null;
    op.tokenError = "invalid_target";
    assertThatThrownBy(tokens::getToken)
        .isInstanceOf(PortvaktException.class)
        .isNotInstanceOf(PortvaktUnavailableException.class)
        .satisfies(error -> assertThat(((PortvaktException) error).code()).isEqualTo("invalid_target"));
  }

  @Test
  void signsAClientAssertionForPrivateKeyJwt() throws Exception {
    ECKey key = new ECKeyGenerator(Curve.P_256).keyID("app-key-1").generate();
    PortvaktClient portvakt =
        PortvaktClient.create(op.config().clientAuth(ClientAuth.privateKeyJwt(key)).build());
    portvakt.clientCredentials().getToken("archive-service");
    var form = op.tokenForms.get(op.tokenForms.size() - 1);
    assertThat(form)
        .containsEntry("client_id", FakeOp.CLIENT_ID)
        .containsEntry("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    SignedJWT assertion = SignedJWT.parse(form.get("client_assertion"));
    assertThat(assertion.verify(new ECDSAVerifier(key.toPublicJWK()))).isTrue();
    assertThat(assertion.getHeader().getKeyID()).isEqualTo("app-key-1");
    assertThat(assertion.getJWTClaimsSet().getIssuer()).isEqualTo(FakeOp.CLIENT_ID);
    assertThat(assertion.getJWTClaimsSet().getSubject()).isEqualTo(FakeOp.CLIENT_ID);
    assertThat(assertion.getJWTClaimsSet().getAudience()).containsExactly(op.issuer);
  }

  @Test
  void requiresClientAuthentication() {
    PortvaktClient portvakt = PortvaktClient.create(op.config().clientAuth(null).build());
    assertThatThrownBy(portvakt::clientCredentials).isInstanceOf(PortvaktConfigException.class);
  }
}
