package se.portvakt.spring.login;

import jakarta.servlet.http.HttpSession;
import java.io.Serializable;
import java.time.Duration;
import java.time.Instant;

/**
 * What the starter keeps in the HTTP session besides Spring Security's context. The tokens are
 * never in the session: they live in the {@link PortvaktTokenStore} under {@code grantId}, a
 * random id made at the login (it survives Spring Security's session id change). A session
 * snapshot that another request wrote back (Spring Session) therefore never brings an old
 * refresh token back.
 *
 * @param createdAt the login
 * @param endsAt the absolute end: the ID token's {@code session_exp}, capped by the maximum age
 * @param outageSince the first failed refresh of an ongoing outage, or {@code null}
 * @param lastSeenAt the last activity (a protected request or an access token use)
 * @param grantId the key of the session's tokens in the token store
 */
public record PortvaktSessionState(
    Instant createdAt, Instant endsAt, Instant outageSince, Instant lastSeenAt, String grantId)
    implements Serializable {

  /** The session attribute holding the state. */
  public static final String ATTRIBUTE = PortvaktSessionState.class.getName();

  /** The state of a session, or {@code null}. */
  public static PortvaktSessionState of(HttpSession session) {
    if (session == null) return null;
    try {
      return session.getAttribute(ATTRIBUTE) instanceof PortvaktSessionState state ? state : null;
    } catch (IllegalStateException invalidated) {
      return null;
    }
  }

  public void storeIn(HttpSession session) {
    session.setAttribute(ATTRIBUTE, this);
  }

  /** Whether the session has ended: its absolute end, or {@code idleTimeout} without activity. */
  public boolean endedAt(Instant now, Duration idleTimeout) {
    return !now.isBefore(endsAt) || now.isAfter(lastSeenAt.plus(idleTimeout));
  }

  /** When the session ends unless used again. */
  public Instant expiresAt(Duration idleTimeout) {
    Instant idle = lastSeenAt.plus(idleTimeout);
    return idle.isBefore(endsAt) ? idle : endsAt;
  }

  public PortvaktSessionState withEndsAt(Instant value) {
    return new PortvaktSessionState(createdAt, value, outageSince, lastSeenAt, grantId);
  }

  public PortvaktSessionState withOutageSince(Instant value) {
    return new PortvaktSessionState(createdAt, endsAt, value, lastSeenAt, grantId);
  }

  public PortvaktSessionState withLastSeenAt(Instant value) {
    return new PortvaktSessionState(createdAt, endsAt, outageSince, value, grantId);
  }
}
