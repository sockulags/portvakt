package se.portvakt.sdk;

import java.util.List;

/** The SDK configuration is invalid. The message lists every problem, never a secret value. */
public class PortvaktConfigException extends PortvaktException {
  private static final long serialVersionUID = 1L;

  private final List<String> issues;

  public PortvaktConfigException(List<String> issues) {
    super("invalid_config", "Invalid Portvakt SDK configuration:\n- " + String.join("\n- ", issues), 500);
    this.issues = List.copyOf(issues);
  }

  /** Each problem as {@code path: message}. */
  public List<String> issues() {
    return issues;
  }
}
