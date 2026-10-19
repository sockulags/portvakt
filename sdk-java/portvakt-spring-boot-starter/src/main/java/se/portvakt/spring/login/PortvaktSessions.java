package se.portvakt.spring.login;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;

/** Ending and touching browser sessions (the session, its state and its tokens together). */
public class PortvaktSessions {
  private static final Logger LOG = LoggerFactory.getLogger(PortvaktSessions.class);

  private final PortvaktTokenStore store;
  private final PortvaktLoginSettings settings;
  private final Clock clock;

  public PortvaktSessions(PortvaktTokenStore store, PortvaktLoginSettings settings, Clock clock) {
    this.store = store;
    this.settings = settings;
    this.clock = clock;
  }

  public PortvaktTokenStore store() {
    return store;
  }

  public PortvaktLoginSettings settings() {
    return settings;
  }

  public Clock clock() {
    return clock;
  }

  /** Whether the state's session is over (its absolute end or the idle timeout). */
  public boolean ended(PortvaktSessionState state) {
    return state == null || state.endedAt(clock.instant(), settings.idleTimeout());
  }

  /** Records activity, at most once per {@link #touchInterval()}. */
  public PortvaktSessionState touch(HttpSession session, PortvaktSessionState state) {
    Instant now = clock.instant();
    if (Duration.between(state.lastSeenAt(), now).compareTo(touchInterval()) < 0) return state;
    PortvaktSessionState touched = state.withLastSeenAt(now);
    try {
      touched.storeIn(session);
    } catch (IllegalStateException invalidated) {
      return state;
    }
    return touched;
  }

  /** Ends the request's session: its tokens, the HTTP session and the security context. */
  public void end(HttpServletRequest request) {
    HttpSession session = request.getSession(false);
    PortvaktSessionState state = PortvaktSessionState.of(session);
    if (state != null && state.grantId() != null) {
      try {
        store.delete(state.grantId());
      } catch (RuntimeException failed) {
        LOG.warn("could not delete the session's tokens: {}", failed.getClass().getSimpleName());
      }
    }
    if (session != null) {
      try {
        session.invalidate();
      } catch (IllegalStateException alreadyInvalid) {
        // Nothing left to end.
      }
    }
    SecurityContextHolder.clearContext();
  }

  /** Activity is recorded at most this often (a quarter of the idle timeout, at most 60 s). */
  public Duration touchInterval() {
    Duration quarter = settings.idleTimeout().dividedBy(4);
    return quarter.compareTo(Duration.ofSeconds(60)) < 0 ? quarter : Duration.ofSeconds(60);
  }
}
