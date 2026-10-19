package se.portvakt.demo;

import org.springframework.boot.context.properties.ConfigurationProperties;
import se.portvakt.sdk.AcrRanking;

/**
 * The demo's own settings ({@code demo.*}).
 *
 * @param appName the name shown on the pages
 * @param stepUpAcr the acr of "Kräv högre säkerhetsnivå"
 * @param apiUrl where the demo calls its own API (the instance itself, from the inside)
 * @param production refuses development secrets and an http issuer
 */
@ConfigurationProperties(prefix = "demo")
public record DemoProperties(String appName, String stepUpAcr, String apiUrl, boolean production) {
  /** The development client secret; refused with {@code demo.production=true}. */
  public static final String DEV_CLIENT_SECRET = "dev-only-service-c-client-secret-0123456789";

  public DemoProperties {
    if (appName == null || appName.isBlank()) appName = "Tjänst C";
    if (stepUpAcr == null || stepUpAcr.isBlank()) stepUpAcr = AcrRanking.LOA4;
    if (apiUrl == null || apiUrl.isBlank()) apiUrl = "http://127.0.0.1:3300";
  }
}
