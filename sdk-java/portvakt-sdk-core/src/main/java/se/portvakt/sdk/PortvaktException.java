package se.portvakt.sdk;

/**
 * Base class of every error the SDK throws on purpose. {@link #code()} is stable and safe to
 * show; messages never contain tokens, secrets or personal data.
 */
public class PortvaktException extends RuntimeException {
  private static final long serialVersionUID = 1L;

  private final String code;
  private final int status;

  public PortvaktException(String code, String message, int status) {
    this(code, message, status, null);
  }

  public PortvaktException(String code, String message, int status, Throwable cause) {
    super(message, cause);
    this.code = code;
    this.status = status;
  }

  /** Stable machine-readable error code, for example {@code portvakt_unavailable}. */
  public String code() {
    return code;
  }

  /** The HTTP status the SDK answers with for this error. */
  public int status() {
    return status;
  }
}
