package se.portvakt.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.postgresql.ds.PGSimpleDataSource;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContextHolder;
import se.portvakt.spring.login.JdbcTokenStore;
import se.portvakt.spring.login.PortvaktSessionState;
import se.portvakt.spring.login.PortvaktTokenStore;
import se.portvakt.spring.login.TokenSealer;

/**
 * The JDBC token store against the test stack's Postgres (npm run test:java passes
 * portvakt.it.jdbc-url): one refresh for concurrent session snapshots, sealed contents, single
 * use of pending logins, cleanup.
 */
@ExtendWith(JdbcTokenStoreIT.Stack.class)
class JdbcTokenStoreIT {
  static final String URL = System.getProperty("portvakt.it.jdbc-url", "");
  static final String TABLE = "portvakt_grant_it";
  static final String KEY = Base64.getEncoder().encodeToString("it-token-store-key-32-bytes-long".getBytes(StandardCharsets.UTF_8));

  static final class Stack implements ExecutionCondition {
    @Override
    public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext context) {
      if (!URL.isEmpty()) return ConditionEvaluationResult.enabled("Postgres at " + URL);
      if (Boolean.getBoolean("portvakt.it.required")) throw new IllegalStateException("portvakt.it.jdbc-url is not set");
      return ConditionEvaluationResult.disabled("no Postgres: run npm run test:java");
    }
  }

  static FakeProvider provider;
  static PGSimpleDataSource dataSource;

  @BeforeAll
  static void start() throws Exception {
    provider = new FakeProvider();
    dataSource = new PGSimpleDataSource();
    dataSource.setUrl(URL);
    dataSource.setUser(System.getProperty("portvakt.it.jdbc-user", "portvakt"));
    dataSource.setPassword(System.getProperty("portvakt.it.jdbc-password", "portvakt"));
    try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
      statement.execute("DROP TABLE IF EXISTS " + TABLE);
    }
  }

  @AfterAll
  static void stop() {
    if (provider != null) provider.close();
  }

  static JdbcTokenStore store(Clock clock) {
    JdbcTokenStore store = new JdbcTokenStore(dataSource, new TokenSealer(List.of(KEY)), clock, Duration.ofSeconds(15), TABLE);
    store.initializeSchema();
    return store;
  }

  @Test
  void refreshesOnceForTwoConcurrentRequestsWithSeparateSessionSnapshots() throws Exception {
    // Two logins (two "replicas") sharing the database.
    TestLogin first = new TestLogin(provider, Duration.ZERO, JdbcTokenStoreIT::store);
    TestLogin second = new TestLogin(provider, Duration.ZERO, JdbcTokenStoreIT::store);
    MockHttpSession a = first.signIn(Instant.now().plusSeconds(3600));
    MockHttpSession b = TestLogin.copy(a);
    int before = provider.refreshGrants.get();
    provider.tokenDelayMillis = 400;
    provider.accessTokenLifetime = 7200;
    CountDownLatch go = new CountDownLatch(1);
    ExecutorService threads = Executors.newFixedThreadPool(2);
    try {
      List<Callable<String>> calls =
          List.of(
              () -> call(go, first, a),
              () -> call(go, second, b));
      List<Future<String>> results = calls.stream().map(threads::submit).toList();
      go.countDown();
      assertThat(results.get(0).get()).isEqualTo(results.get(1).get()).isNotEqualTo("access-initial");
    } finally {
      threads.shutdownNow();
      provider.tokenDelayMillis = 0;
      provider.accessTokenLifetime = 300;
    }
    assertThat(provider.refreshGrants.get() - before).isEqualTo(1);
    String grantId = PortvaktSessionState.of(a).grantId();
    assertThat(first.store.load(grantId).refreshToken()).isEqualTo(provider.currentRefreshToken);
  }

  static String call(CountDownLatch go, TestLogin login, MockHttpSession session) throws Exception {
    go.await();
    try {
      return login.tokens.getAccessToken(login.request(session), new MockHttpServletResponse(), Duration.ofHours(1));
    } finally {
      SecurityContextHolder.clearContext();
    }
  }

  @Test
  void sealsTheContentsWithTheRowKeyAsAdditionalData() throws Exception {
    JdbcTokenStore store = store(Clock.systemUTC());
    PortvaktTokenStore.StoredTokens tokens =
        new PortvaktTokenStore.StoredTokens("secret-access-token", Instant.now(), Instant.now().plusSeconds(300), Set.of("openid"), "secret-refresh-token");
    store.save("grant-a", tokens, Instant.now().plusSeconds(600));
    byte[] sealed;
    try (Connection connection = dataSource.getConnection();
        PreparedStatement select = connection.prepareStatement("SELECT sealed FROM " + TABLE + " WHERE grant_id = ?")) {
      select.setString(1, "grant-a");
      try (ResultSet row = select.executeQuery()) {
        assertThat(row.next()).isTrue();
        sealed = row.getBytes(1);
      }
    }
    String raw = new String(sealed, StandardCharsets.ISO_8859_1);
    assertThat(raw).doesNotContain("secret-access-token").doesNotContain("secret-refresh-token");
    assertThat(store.load("grant-a").refreshToken()).isEqualTo("secret-refresh-token");
    // Moved to another row, it does not open; with another key neither.
    TokenSealer sealer = new TokenSealer(List.of(KEY));
    assertThat(sealer.open(sealed, "grant-a")).isNotNull();
    assertThat(sealer.open(sealed, "grant-b")).isNull();
    assertThat(new TokenSealer(List.of(Base64.getEncoder().encodeToString(new byte[32]))).open(sealed, "grant-a")).isNull();
    // A rotated key list still opens it.
    assertThat(new TokenSealer(List.of(Base64.getEncoder().encodeToString(new byte[32]), KEY)).open(sealed, "grant-a"))
        .isNotNull();
  }

  @Test
  void givesAPendingLoginToExactlyOneOfConcurrentCallersAndDeletesExpiredRows() throws Exception {
    JdbcTokenStore store = store(Clock.systemUTC());
    store.savePending("login-1", "pending".getBytes(StandardCharsets.UTF_8), Instant.now().plusSeconds(600));
    assertThat(store.loadPending("login-1")).isNotNull();
    ExecutorService threads = Executors.newFixedThreadPool(4);
    CountDownLatch go = new CountDownLatch(1);
    List<Future<byte[]>> takes;
    try {
      takes =
          java.util.stream.IntStream.range(0, 4)
              .mapToObj(
                  index ->
                      threads.submit(
                          () -> {
                            go.await();
                            return store.takePending("login-1");
                          }))
              .toList();
      go.countDown();
      long winners = 0;
      for (Future<byte[]> take : takes) if (take.get() != null) winners++;
      assertThat(winners).isEqualTo(1);
    } finally {
      threads.shutdownNow();
    }
    store.save(
        "expired",
        new PortvaktTokenStore.StoredTokens("a", Instant.now().minusSeconds(60), Instant.now().minusSeconds(30), Set.of(), "r"),
        Instant.now().minusSeconds(1));
    assertThat(store.load("expired")).isNull();
    assertThat(store.deleteExpired()).isGreaterThanOrEqualTo(1);
  }
}
