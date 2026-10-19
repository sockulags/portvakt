package se.portvakt.spring.login;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.UnaryOperator;

/**
 * The default token store: in this process only. Correct for one instance (also with Spring
 * Session's snapshots, since the session holds only the grant id), but tokens are lost on a
 * restart and other replicas cannot see them: use {@link JdbcTokenStore} for several instances.
 */
public class InMemoryTokenStore implements PortvaktTokenStore {
  private static final int LOCK_STRIPES = 256;

  private record Entry(Object value, Instant expiresAt) {}

  private final Clock clock;
  private final Map<String, Entry> grants = new ConcurrentHashMap<>();
  private final Map<String, Entry> pending = new ConcurrentHashMap<>();
  private final ReentrantLock[] locks = new ReentrantLock[LOCK_STRIPES];

  public InMemoryTokenStore(Clock clock) {
    this.clock = clock;
    for (int index = 0; index < LOCK_STRIPES; index++) locks[index] = new ReentrantLock();
  }

  @Override
  public void save(String grantId, StoredTokens tokens, Instant expiresAt) {
    grants.put(grantId, new Entry(tokens, expiresAt));
  }

  @Override
  public StoredTokens load(String grantId) {
    Entry entry = live(grants, grantId);
    return entry == null ? null : (StoredTokens) entry.value;
  }

  @Override
  public StoredTokens update(String grantId, UnaryOperator<StoredTokens> update) {
    ReentrantLock lock = locks[Math.floorMod(grantId.hashCode(), LOCK_STRIPES)];
    lock.lock();
    try {
      Entry entry = live(grants, grantId);
      StoredTokens current = entry == null ? null : (StoredTokens) entry.value;
      StoredTokens next = update.apply(current);
      if (next != null && next != current && entry != null) grants.put(grantId, new Entry(next, entry.expiresAt));
      return next == null ? current : next;
    } finally {
      lock.unlock();
    }
  }

  @Override
  public void expire(String grantId, Instant expiresAt) {
    grants.computeIfPresent(grantId, (key, entry) -> new Entry(entry.value, expiresAt));
  }

  @Override
  public void delete(String grantId) {
    grants.remove(grantId);
  }

  @Override
  public void savePending(String key, byte[] value, Instant expiresAt) {
    pending.put(key, new Entry(value.clone(), expiresAt));
  }

  @Override
  public byte[] loadPending(String key) {
    Entry entry = live(pending, key);
    return entry == null ? null : ((byte[]) entry.value).clone();
  }

  @Override
  public byte[] takePending(String key) {
    Entry entry = pending.remove(key);
    if (entry == null || !clock.instant().isBefore(entry.expiresAt)) return null;
    return (byte[]) entry.value;
  }

  @Override
  public void deletePending(String key) {
    pending.remove(key);
  }

  @Override
  public int deleteExpired() {
    Instant now = clock.instant();
    int before = grants.size() + pending.size();
    grants.values().removeIf(entry -> !now.isBefore(entry.expiresAt));
    pending.values().removeIf(entry -> !now.isBefore(entry.expiresAt));
    return before - grants.size() - pending.size();
  }

  private Entry live(Map<String, Entry> map, String key) {
    Entry entry = map.get(key);
    if (entry == null) return null;
    if (!clock.instant().isBefore(entry.expiresAt)) {
      map.remove(key, entry);
      return null;
    }
    return entry;
  }
}
