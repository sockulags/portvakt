package se.portvakt.spring;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requires a person whose assurance level is at least {@link #value()} for a Spring MVC handler
 * (a method, or every method of a controller). Browser sessions below it are sent to the step-up
 * ({@code {base}/step-up?acr=...}; XHR gets 401 {@code {"error": "step_up_required", "acr",
 * "stepUpUrl"}}); bearer tokens get 401 {@code insufficient_user_authentication} with {@code
 * acr_values} (RFC 9470); service tokens are refused (403 {@code insufficient_scope}).
 *
 * <pre>{@code
 * @RequireAcr(AcrRanking.LOA4)
 * @PostMapping("/cases/{id}/decide")
 * String decide(...) { ... }
 * }</pre>
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface RequireAcr {
  /** The minimum acr, for example {@code http://id.elegnamnden.se/loa/1.0/loa4}. */
  String value();
}
