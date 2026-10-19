package se.portvakt.demo.it;

import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * The real Portvakt the integration tests run against, from system properties that {@code npm
 * run test:java} passes to Maven. Without them the tests are skipped, unless {@code
 * portvakt.it.required=true} (the orchestrator, CI): then they fail.
 */
public final class PortvaktStack implements ExecutionCondition {
  public static final String ISSUER = System.getProperty("portvakt.it.issuer", "");
  public static final String ISOLATION_ISSUER = System.getProperty("portvakt.it.isolation-issuer", "");
  public static final String CLIENT_SECRET = System.getProperty("portvakt.it.client-secret", "");
  public static final String MOCK_IDP = System.getProperty("portvakt.it.mock-idp", "");
  /** service-d's private JWK (private_key_jwt), made for this run by the orchestrator. */
  public static final String PRIVATE_JWK = System.getProperty("portvakt.it.private-jwk", "");
  public static final boolean REQUIRED = Boolean.getBoolean("portvakt.it.required");

  /** The Java demo inside the Maven container (the redirect URI the seed registers). */
  public static final String APP = "http://localhost:3300";

  @Override
  public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext context) {
    if (!ISSUER.isEmpty()) return ConditionEvaluationResult.enabled("Portvakt at " + ISSUER);
    if (REQUIRED) throw new IllegalStateException("portvakt.it.required is set but portvakt.it.issuer is not");
    return ConditionEvaluationResult.disabled("no Portvakt: run npm run test:java");
  }

  public static String portvaktOrigin() {
    return FlowDriver.originOf(ISSUER);
  }
}
