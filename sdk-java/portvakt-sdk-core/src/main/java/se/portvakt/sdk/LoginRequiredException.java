package se.portvakt.sdk;

/** The request has no (longer a) valid browser session: the person must sign in again (401). */
public class LoginRequiredException extends PortvaktException {
  private static final long serialVersionUID = 1L;

  /** Why a session ended or does not exist. */
  public enum Reason {
    /** No session at all. */
    NO_SESSION("no_session"),
    /** The broker session's {@code session_exp}, the application's maximum age or idle timeout. */
    SESSION_EXPIRED("session_expired"),
    /** Portvakt refused the refresh token: revoked, replayed or the broker session ended. */
    REFRESH_FAILED("refresh_failed"),
    /** Portvakt stayed unreachable longer than the outage grace. */
    OUTAGE_GRACE_EXCEEDED("outage_grace_exceeded");

    private final String code;

    Reason(String code) {
      this.code = code;
    }

    public String code() {
      return code;
    }
  }

  private final Reason reason;

  public LoginRequiredException(Reason reason) {
    super("login_required", "Sign-in required (" + reason.code() + ")", 401);
    this.reason = reason;
  }

  public Reason reason() {
    return reason;
  }
}
