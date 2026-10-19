package se.portvakt.spring;

import org.springframework.boot.diagnostics.AbstractFailureAnalyzer;
import org.springframework.boot.diagnostics.FailureAnalysis;
import se.portvakt.sdk.PortvaktConfigException;

/** Start-up failure report for invalid {@code portvakt.*} properties (never echoes values). */
class PortvaktConfigFailureAnalyzer extends AbstractFailureAnalyzer<PortvaktConfigException> {
  @Override
  protected FailureAnalysis analyze(Throwable rootFailure, PortvaktConfigException cause) {
    return new FailureAnalysis(
        "The Portvakt configuration is invalid:\n  - " + String.join("\n  - ", cause.issues()),
        "Fix the portvakt.* properties listed above (see the Portvakt Java SDK README).",
        cause);
  }
}
