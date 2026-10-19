package se.portvakt.spring.login;

import java.io.IOException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.ResourceAccessException;
import se.portvakt.sdk.PortvaktUnavailableException;

/** Classifies failures of requests to Portvakt. */
public final class Failures {
  private Failures() {}

  /**
   * Whether a failure means Portvakt is unreachable: a network error, a timeout, or a 5xx answer
   * anywhere in the cause chain.
   */
  public static boolean isUnavailable(Throwable error) {
    Throwable current = error;
    for (int depth = 0; current != null && depth < 10; depth++) {
      if (current instanceof PortvaktUnavailableException
          || current instanceof ResourceAccessException
          || current instanceof HttpServerErrorException
          || current instanceof IOException) {
        return true;
      }
      if (current instanceof HttpStatusCodeException status && status.getStatusCode().is5xxServerError()) {
        return true;
      }
      if (current.getCause() == current) break;
      current = current.getCause();
    }
    return false;
  }

  /** The first cause of the given type, or {@code null}. */
  public static <T extends Throwable> T find(Throwable error, Class<T> type) {
    Throwable current = error;
    for (int depth = 0; current != null && depth < 10; depth++) {
      if (type.isInstance(current)) return type.cast(current);
      if (current.getCause() == current) break;
      current = current.getCause();
    }
    return null;
  }
}
