package se.portvakt.sdk;

import java.time.Duration;

/**
 * Portvakt could not be reached: a network error, a timeout or a 5xx answer (HTTP 503); or it
 * asked to be retried later ({@link PortvaktRetryLaterException}).
 */
public class PortvaktUnavailableException extends PortvaktException {
  private static final long serialVersionUID = 1L;

  private final Duration retryAfter;

  public PortvaktUnavailableException(String message) {
    this(message, null, null);
  }

  public PortvaktUnavailableException(String message, Throwable cause) {
    this(message, cause, null);
  }

  /**
   * @param retryAfter Portvakt's {@code Retry-After}, or {@code null} when it sent none (the SDK's
   *     503 passes it on)
   */
  public PortvaktUnavailableException(String message, Throwable cause, Duration retryAfter) {
    super("portvakt_unavailable", message, 503, cause);
    this.retryAfter = retryAfter;
  }

  /** Portvakt's {@code Retry-After}, or {@code null}. */
  public Duration retryAfter() {
    return retryAfter;
  }
}
