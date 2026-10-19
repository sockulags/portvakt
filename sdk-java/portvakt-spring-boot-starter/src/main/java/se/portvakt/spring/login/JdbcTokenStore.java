package se.portvakt.spring.login;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.portvakt.sdk.PortvaktUnavailableException;

/**
 * Token store in a database table (PostgreSQL; the schema is {@code
 * META-INF/portvakt/schema-postgresql.sql}):
 *
 * <pre>
 * portvakt_grant(grant_id varchar(128) primary key, sealed bytea not null, expires_at timestamptz not null)
 * </pre>
 *
 * Contents are sealed with AES-256-GCM ({@link TokenSealer}, the row key as additional data);
 * the table holds no token in the clear. {@link #update} runs in one short transaction of its
 * own connection: {@code SELECT ... FOR UPDATE} (with a lock timeout), the update (a refresh at
 * Portvakt), {@code UPDATE}, commit; concurrent updates of the same grant wait and then see the
 * refreshed tokens. Pending logins are rows {@code pending:<key>}, taken with a locked delete.
 */
public class JdbcTokenStore implements PortvaktTokenStore {
  private static final Logger LOG = LoggerFactory.getLogger(JdbcTokenStore.class);
  private static final Pattern TABLE = Pattern.compile("^[A-Za-z_][A-Za-z0-9_]{0,62}(\\.[A-Za-z_][A-Za-z0-9_]{0,62})?$");
  private static final String PENDING = "pending:";

  private final DataSource dataSource;
  private final TokenSealer sealer;
  private final Clock clock;
  private final Duration lockTimeout;
  private final String table;

  public JdbcTokenStore(DataSource dataSource, TokenSealer sealer, Clock clock, Duration lockTimeout, String table) {
    if (!TABLE.matcher(table).matches()) throw new IllegalArgumentException("invalid table name");
    this.dataSource = dataSource;
    this.sealer = sealer;
    this.clock = clock;
    this.lockTimeout = lockTimeout;
    this.table = table;
  }

  /** The schema (CREATE TABLE IF NOT EXISTS), for migrations or {@link #initializeSchema()}. */
  public static String schema(String table) {
    try (InputStream in = JdbcTokenStore.class.getResourceAsStream("/META-INF/portvakt/schema-postgresql.sql")) {
      if (in == null) throw new IllegalStateException("schema resource missing");
      return new String(in.readAllBytes(), StandardCharsets.UTF_8).replace("portvakt_grant", table);
    } catch (IOException exception) {
      throw new IllegalStateException(exception);
    }
  }

  /** Creates the table and its index when missing. */
  public void initializeSchema() {
    run(
        connection -> {
          try (Statement statement = connection.createStatement()) {
            String withoutComments = schema(table).replaceAll("(?m)^[ \\t]*--.*$", "");
            for (String sql : withoutComments.split(";")) {
              String trimmed = sql.trim();
              if (!trimmed.isEmpty()) statement.execute(trimmed);
            }
          }
          return null;
        });
  }

  @Override
  public void save(String grantId, StoredTokens tokens, Instant expiresAt) {
    put(grantId, tokens.toJson().getBytes(StandardCharsets.UTF_8), expiresAt);
  }

  @Override
  public StoredTokens load(String grantId) {
    byte[] plaintext = get(grantId);
    return plaintext == null ? null : StoredTokens.fromJson(new String(plaintext, StandardCharsets.UTF_8));
  }

  @Override
  public StoredTokens update(String grantId, UnaryOperator<StoredTokens> update) {
    return transaction(
        connection -> {
          StoredTokens current = null;
          try (PreparedStatement select =
              connection.prepareStatement("SELECT sealed, expires_at FROM " + table + " WHERE grant_id = ? FOR UPDATE")) {
            select.setQueryTimeout(seconds(lockTimeout));
            select.setString(1, grantId);
            try (ResultSet row = select.executeQuery()) {
              if (row.next() && clock.instant().isBefore(row.getObject(2, OffsetDateTime.class).toInstant())) {
                byte[] plaintext = sealer.open(row.getBytes(1), grantId);
                if (plaintext != null) current = StoredTokens.fromJson(new String(plaintext, StandardCharsets.UTF_8));
              }
            }
          }
          StoredTokens next = update.apply(current);
          if (next != null && next != current && current != null) {
            try (PreparedStatement write = connection.prepareStatement("UPDATE " + table + " SET sealed = ? WHERE grant_id = ?")) {
              write.setBytes(1, sealer.seal(next.toJson().getBytes(StandardCharsets.UTF_8), grantId));
              write.setString(2, grantId);
              write.executeUpdate();
            }
          }
          return next == null ? current : next;
        });
  }

  @Override
  public void expire(String grantId, Instant expiresAt) {
    run(
        connection -> {
          try (PreparedStatement statement =
              connection.prepareStatement("UPDATE " + table + " SET expires_at = ? WHERE grant_id = ?")) {
            statement.setObject(1, OffsetDateTime.ofInstant(expiresAt, ZoneOffset.UTC));
            statement.setString(2, grantId);
            statement.executeUpdate();
          }
          return null;
        });
  }

  @Override
  public void delete(String grantId) {
    remove(grantId);
  }

  @Override
  public void savePending(String key, byte[] value, Instant expiresAt) {
    put(PENDING + key, value, expiresAt);
  }

  @Override
  public byte[] loadPending(String key) {
    return get(PENDING + key);
  }

  @Override
  public byte[] takePending(String key) {
    String rowKey = PENDING + key;
    return transaction(
        connection -> {
          byte[] sealed = null;
          Instant expiresAt = null;
          try (PreparedStatement select =
              connection.prepareStatement("SELECT sealed, expires_at FROM " + table + " WHERE grant_id = ? FOR UPDATE")) {
            select.setQueryTimeout(seconds(lockTimeout));
            select.setString(1, rowKey);
            try (ResultSet row = select.executeQuery()) {
              if (row.next()) {
                sealed = row.getBytes(1);
                expiresAt = row.getObject(2, OffsetDateTime.class).toInstant();
              }
            }
          }
          if (sealed == null) return null;
          int deleted;
          try (PreparedStatement delete = connection.prepareStatement("DELETE FROM " + table + " WHERE grant_id = ?")) {
            delete.setString(1, rowKey);
            deleted = delete.executeUpdate();
          }
          if (deleted != 1 || !clock.instant().isBefore(expiresAt)) return null;
          return sealer.open(sealed, rowKey);
        });
  }

  @Override
  public void deletePending(String key) {
    remove(PENDING + key);
  }

  @Override
  public int deleteExpired() {
    return run(
        connection -> {
          try (PreparedStatement statement = connection.prepareStatement("DELETE FROM " + table + " WHERE expires_at < ?")) {
            statement.setObject(1, OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC));
            return statement.executeUpdate();
          }
        });
  }

  // Internals ----------------------------------------------------------------------------------

  private void put(String rowKey, byte[] plaintext, Instant expiresAt) {
    byte[] sealed = sealer.seal(plaintext, rowKey);
    OffsetDateTime expiry = OffsetDateTime.ofInstant(expiresAt, ZoneOffset.UTC);
    transaction(
        connection -> {
          int updated;
          try (PreparedStatement update =
              connection.prepareStatement("UPDATE " + table + " SET sealed = ?, expires_at = ? WHERE grant_id = ?")) {
            update.setBytes(1, sealed);
            update.setObject(2, expiry);
            update.setString(3, rowKey);
            updated = update.executeUpdate();
          }
          if (updated == 0) {
            try (PreparedStatement insert =
                connection.prepareStatement("INSERT INTO " + table + " (grant_id, sealed, expires_at) VALUES (?, ?, ?)")) {
              insert.setString(1, rowKey);
              insert.setBytes(2, sealed);
              insert.setObject(3, expiry);
              insert.executeUpdate();
            }
          }
          return null;
        });
  }

  private byte[] get(String rowKey) {
    return run(
        connection -> {
          try (PreparedStatement select =
              connection.prepareStatement("SELECT sealed, expires_at FROM " + table + " WHERE grant_id = ?")) {
            select.setString(1, rowKey);
            try (ResultSet row = select.executeQuery()) {
              if (!row.next()) return null;
              if (!clock.instant().isBefore(row.getObject(2, OffsetDateTime.class).toInstant())) return null;
              byte[] plaintext = sealer.open(row.getBytes(1), rowKey);
              if (plaintext == null) LOG.warn("a token store row could not be opened (wrong key?)");
              return plaintext;
            }
          }
        });
  }

  private void remove(String rowKey) {
    run(
        connection -> {
          try (PreparedStatement delete = connection.prepareStatement("DELETE FROM " + table + " WHERE grant_id = ?")) {
            delete.setString(1, rowKey);
            delete.executeUpdate();
          }
          return null;
        });
  }

  private interface Work<T> {
    T apply(Connection connection) throws SQLException;
  }

  /** Auto-commit work. */
  private <T> T run(Work<T> work) {
    try (Connection connection = dataSource.getConnection()) {
      connection.setAutoCommit(true);
      return work.apply(connection);
    } catch (SQLException exception) {
      throw unavailable(exception);
    }
  }

  /** One transaction with a lock timeout; rolled back when the work throws. */
  private <T> T transaction(Work<T> work) {
    try (Connection connection = dataSource.getConnection()) {
      connection.setAutoCommit(false);
      try {
        if (connection.getMetaData().getDatabaseProductName().toLowerCase(java.util.Locale.ROOT).contains("postgres")) {
          try (Statement statement = connection.createStatement()) {
            statement.execute("SET LOCAL lock_timeout = '" + Math.max(1, lockTimeout.toMillis()) + "ms'");
          }
        }
        T result = work.apply(connection);
        connection.commit();
        return result;
      } catch (SQLException | RuntimeException failure) {
        try {
          connection.rollback();
        } catch (SQLException ignored) {
          // The connection is closed below.
        }
        throw failure;
      } finally {
        connection.setAutoCommit(true);
      }
    } catch (SQLException exception) {
      throw unavailable(exception);
    }
  }

  private static RuntimeException unavailable(SQLException exception) {
    LOG.warn("token store failed: {}", exception.getSQLState());
    return new PortvaktUnavailableException("the token store is unavailable", exception);
  }

  private static int seconds(Duration duration) {
    return (int) Math.max(1, Math.min(Integer.MAX_VALUE, (duration.toMillis() + 999) / 1000));
  }
}
