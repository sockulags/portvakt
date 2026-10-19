package se.portvakt.sdk;

/** Portvakt could not be reached: a network error, a timeout or a 5xx answer (HTTP 503). */
public class PortvaktUnavailableException extends PortvaktException {
  private static final long serialVersionUID = 1L;

  public PortvaktUnavailableException(String message) {
    super("portvakt_unavailable", message, 503);
  }

  public PortvaktUnavailableException(String message, Throwable cause) {
    super("portvakt_unavailable", message, 503, cause);
  }
}
