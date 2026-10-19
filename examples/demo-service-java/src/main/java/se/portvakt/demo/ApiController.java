package se.portvakt.demo;

import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import se.portvakt.sdk.PortvaktPrincipal;
import se.portvakt.spring.PortvaktSecurity;

/**
 * The demo's API (resource server chain, {@code /api/**}): who called, as the access token says.
 * Person and service tokens are accepted ({@code portvakt.resource-server.allow-service}).
 */
@RestController
class ApiController {
  private final DemoProperties properties;

  ApiController(DemoProperties properties) {
    this.properties = properties;
  }

  @GetMapping("/api/whoami")
  Map<String, Object> whoami() {
    PortvaktPrincipal principal = PortvaktSecurity.currentPrincipal().orElseThrow();
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("app", properties.appName());
    body.put("principal", describe(principal));
    return body;
  }

  private static Map<String, Object> describe(PortvaktPrincipal principal) {
    Map<String, Object> json = new LinkedHashMap<>();
    json.put("isService", principal.isService());
    if (principal.isService()) {
      json.put("clientId", principal.clientId());
      json.put("tenant", principal.tenant());
      return json;
    }
    json.put("sub", principal.sub());
    json.put("tenant", principal.tenant());
    json.put("idpKind", principal.idpKind().claimValue());
    json.put("acr", principal.acr());
    json.put("roles", principal.roles());
    if (principal.rep() == null) {
      json.put("rep", null);
    } else {
      Map<String, Object> rep = new LinkedHashMap<>();
      rep.put("sub", principal.rep().sub());
      rep.put("type", principal.rep().type().claimValue());
      json.put("rep", rep);
    }
    json.put("clientId", principal.clientId());
    return json;
  }
}
