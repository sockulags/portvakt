package se.portvakt.sdk;

import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

/**
 * Portvakt's token endpoint asked to be retried later: HTTP 429 (a rate limit), or the OAuth
 * error {@code temporarily_unavailable} with any status. It refused and rotated nothing, so this
 * is transient: a browser session keeps its unchanged refresh token, no outage starts (the
 * outage grace is not involved), and the request answers 503 with Portvakt's {@code
 * Retry-After}.
 */
public class PortvaktRetryLaterException extends PortvaktUnavailableException {
  private static final long serialVersionUID = 1L;

  public PortvaktRetryLaterException(Duration retryAfter) {
    super("Portvakt asked to retry later", null, retryAfter);
  }

  /**
   * A {@code Retry-After} header value (delta-seconds or an HTTP date) as a duration of 1 s to
   * 1 h, or {@code null} when absent or unreadable.
   */
  public static Duration parseRetryAfter(String value, Instant now) {
    if (value == null || value.isBlank()) return null;
    String trimmed = value.trim();
    long seconds;
    if (trimmed.matches("^\\d{1,10}$")) {
      seconds = Long.parseLong(trimmed);
    } else {
      try {
        Instant at = ZonedDateTime.parse(trimmed, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant();
        seconds = (long) Math.ceil(Duration.between(now, at).toMillis() / 1000.0);
      } catch (DateTimeParseException unreadable) {
        return null;
      }
    }
    return Duration.ofSeconds(Math.min(3600, Math.max(1, seconds)));
  }
}
