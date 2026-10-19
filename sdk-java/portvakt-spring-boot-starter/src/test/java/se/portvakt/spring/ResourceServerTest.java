package se.portvakt.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import se.portvakt.sdk.AcrRanking;

/** The resource server through Spring Security: RFC 6750 answers and per-route requirements. */
@SpringBootTest(
    classes = ResourceServerTest.App.class,
    properties = {
      "portvakt.client-id=case-service",
      "portvakt.allow-insecure-requests=true",
      "portvakt.failure-cache=0s",
      "portvakt.resource-server.enabled=true",
      // The defaults: no service tokens (the default), no representation (enforced everywhere).
      "portvakt.resource-server.allow-representation=false"
    })
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ResourceServerTest {
  static final FakeProvider PROVIDER;

  static {
    try {
      PROVIDER = new FakeProvider();
    } catch (Exception exception) {
      throw new IllegalStateException(exception);
    }
  }

  @AfterAll
  static void stop() {
    PROVIDER.close();
  }

  @DynamicPropertySource
  static void issuer(DynamicPropertyRegistry registry) {
    registry.add("portvakt.issuer", () -> PROVIDER.issuer);
  }

  @Configuration(proxyBeanMethods = false)
  @EnableAutoConfiguration
  @EnableMethodSecurity
  @Import(Routes.class)
  static class App {
    @Bean
    SecurityFilterChain api(HttpSecurity http, PortvaktSecurity portvakt) throws Exception {
      http.with(PortvaktSecurity.resourceServer(), chain -> {});
      http.authorizeHttpRequests(
          requests ->
              requests
                  .requestMatchers("/api/admin").access(portvakt.accessToken(r -> r.roles("admin")))
                  .requestMatchers("/api/loa4").access(portvakt.accessToken(r -> r.acr(AcrRanking.LOA4)))
                  .requestMatchers("/api/service").access(portvakt.accessToken(r -> r.allowServices("other-app")))
                  .requestMatchers("/api/acting").access(portvakt.accessToken(r -> r.allowRepresentation(true)))
                  .requestMatchers("/api/role").hasAuthority("PORTVAKT_ROLE_handlaggare")
                  .requestMatchers("/api/authenticated", "/api/method", "/api/annotated").authenticated()
                  .requestMatchers("/api/open").permitAll()
                  .anyRequest().access(portvakt.accessToken()));
      return http.build();
    }
  }

  @RestController
  static class Routes {
    @GetMapping({"/api/plain", "/api/admin", "/api/loa4", "/api/service", "/api/acting", "/api/role", "/api/authenticated"})
    Map<String, Object> plain() {
      var principal = PortvaktSecurity.currentPrincipal().orElseThrow();
      return Map.of("sub", principal.sub(), "isService", principal.isService());
    }

    @GetMapping("/api/open")
    Map<String, Object> open() {
      return Map.of("principal", PortvaktSecurity.currentPrincipal().isPresent());
    }

    @PreAuthorize("@portvakt.hasRole('handlaggare')")
    @GetMapping("/api/method")
    String method() {
      return "ok";
    }

    @RequireAcr(AcrRanking.LOA4)
    @GetMapping("/api/annotated")
    String annotated() {
      return "ok";
    }
  }

  @Autowired MockMvc mvc;

  static Map<String, Object> person(Object... extra) {
    long now = Instant.now().getEpochSecond();
    Map<String, Object> claims = new HashMap<>();
    claims.put("iss", PROVIDER.issuer);
    claims.put("aud", "case-service");
    claims.put("client_id", "case-service");
    claims.put("sub", "3f2b8c4e-91d7-4a3e-8b6f-2d4c9e1a7b55");
    claims.put("tid", "fake");
    claims.put("idp", "0f1976f6-7f6c-4baf-a88c-2bc6f2e68ce7");
    claims.put("idp_kind", "employee");
    claims.put("acr", AcrRanking.LOA3);
    claims.put("auth_time", now);
    claims.put("roles", List.of("handlaggare"));
    claims.put("attrs", Map.of());
    claims.put("iat", now);
    claims.put("exp", now + 300);
    for (int index = 0; index < extra.length; index += 2) claims.put((String) extra[index], extra[index + 1]);
    return claims;
  }

  static Map<String, Object> service(String clientId) {
    long now = Instant.now().getEpochSecond();
    return new HashMap<>(
        Map.of("iss", PROVIDER.issuer, "aud", "case-service", "client_id", clientId, "sub", clientId, "tid", "fake", "iat", now, "exp", now + 300));
  }

  static String bearer(Map<String, Object> claims) throws Exception {
    SignedJWT jwt =
        new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("key-1").type(new JOSEObjectType("at+jwt")).build(),
            JWTClaimsSet.parse(claims));
    jwt.sign(new ECDSASigner(PROVIDER.key));
    return "Bearer " + jwt.serialize();
  }

  @Test
  @Order(1)
  void answers503WhilePortvaktsKeysCannotBeFetched() throws Exception {
    PROVIDER.down = true;
    try {
      mvc.perform(get("/api/plain").header("Authorization", bearer(person())))
          .andExpect(status().isServiceUnavailable())
          .andExpect(header().string("Retry-After", "5"))
          .andExpect(jsonPath("$.error").value("temporarily_unavailable"));
    } finally {
      PROVIDER.down = false;
    }
  }

  @Test
  @Order(2)
  void answersRfc6750ErrorsForMissingMalformedAndInvalidTokens() throws Exception {
    mvc.perform(get("/api/plain"))
        .andExpect(status().isUnauthorized())
        .andExpect(header().string("WWW-Authenticate", "Bearer realm=\"portvakt\""));
    mvc.perform(get("/api/plain").header("Authorization", "Basic dXNlcjpwYXNz"))
        .andExpect(status().isBadRequest())
        .andExpect(header().string("WWW-Authenticate", org.hamcrest.Matchers.containsString("error=\"invalid_request\"")));
    mvc.perform(get("/api/plain").header("Authorization", "Bearer abc.def.ghi"))
        .andExpect(status().isUnauthorized())
        .andExpect(
            header().string(
                "WWW-Authenticate",
                "Bearer realm=\"portvakt\", error=\"invalid_token\", error_description=\"The access token is invalid\""))
        .andExpect(jsonPath("$.error").value("invalid_token"));
    long now = Instant.now().getEpochSecond();
    mvc.perform(get("/api/plain").header("Authorization", bearer(person("exp", now - 120, "iat", now - 400))))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.error_description").value("The access token has expired"));
    mvc.perform(get("/api/plain").header("Authorization", bearer(person("aud", "service-b"))))
        .andExpect(status().isUnauthorized());
    mvc.perform(get("/api/plain").header("Authorization", bearer(person("iss", PROVIDER.issuer.replace("/t/fake", "/t/other")))))
        .andExpect(status().isUnauthorized());
  }

  @Test
  @Order(3)
  void checksRolesAcrServicesAndRepresentationPerRoute() throws Exception {
    String token = bearer(person());
    mvc.perform(get("/api/plain").header("Authorization", token))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.isService").value(false));
    mvc.perform(get("/api/admin").header("Authorization", token))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.error").value("insufficient_scope"))
        .andExpect(jsonPath("$.reason").value("missing_role"));
    mvc.perform(get("/api/loa4").header("Authorization", token))
        .andExpect(status().isUnauthorized())
        .andExpect(header().string("WWW-Authenticate", org.hamcrest.Matchers.containsString("insufficient_user_authentication")))
        .andExpect(header().string("WWW-Authenticate", org.hamcrest.Matchers.containsString("acr_values=\"" + AcrRanking.LOA4 + "\"")));
    mvc.perform(get("/api/loa4").header("Authorization", bearer(person("acr", AcrRanking.LOA4)))).andExpect(status().isOk());

    String serviceToken = bearer(service("other-app"));
    mvc.perform(get("/api/plain").header("Authorization", serviceToken))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.reason").value("service_not_allowed"));
    mvc.perform(get("/api/service").header("Authorization", serviceToken))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.isService").value(true));
    mvc.perform(get("/api/service").header("Authorization", bearer(service("third-app")))).andExpect(status().isForbidden());

    String acting = bearer(person("rep", Map.of("sub", "party-1", "type", "organisation")));
    mvc.perform(get("/api/plain").header("Authorization", acting))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.reason").value("representation_not_allowed"));
    mvc.perform(get("/api/acting").header("Authorization", acting)).andExpect(status().isOk());
  }

  @Test
  @Order(6)
  void hidesTheRestrictedTokensPrincipalFromCurrentPrincipalUnlessTheRouteAcceptedIt() throws Exception {
    // An open route: a token the defaults refuse yields no principal (it would pass for a person).
    for (String restricted :
        List.of(bearer(service("other-app")), bearer(person("rep", Map.of("sub", "party-1", "type", "organisation"))))) {
      mvc.perform(get("/api/open").header("Authorization", restricted))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.principal").value(false));
    }
    mvc.perform(get("/api/open").header("Authorization", bearer(person())))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.principal").value(true));
    // A route that accepts the service token explicitly still sees it.
    mvc.perform(get("/api/service").header("Authorization", bearer(service("other-app"))))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.isService").value(true));
  }

  @Test
  @Order(5)
  void enforcesTheDefaultsAlsoInRulesThatOnlyAskForAuthentication() throws Exception {
    String serviceToken = bearer(service("other-app"));
    mvc.perform(get("/api/authenticated").header("Authorization", serviceToken))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.error").value("insufficient_scope"))
        .andExpect(jsonPath("$.reason").value("service_not_allowed"));
    String acting = bearer(person("rep", Map.of("sub", "party-1", "type", "person")));
    mvc.perform(get("/api/authenticated").header("Authorization", acting))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.reason").value("representation_not_allowed"));
    // A restricted token has no authorities and fails method security too.
    mvc.perform(get("/api/role").header("Authorization", acting)).andExpect(status().isForbidden());
    mvc.perform(get("/api/method").header("Authorization", acting)).andExpect(status().isForbidden());
    // Unrestricted tokens pass.
    mvc.perform(get("/api/authenticated").header("Authorization", bearer(person()))).andExpect(status().isOk());
    mvc.perform(get("/api/role").header("Authorization", bearer(person()))).andExpect(status().isOk());
  }

  @Test
  @Order(4)
  void supportsMethodSecurityAndRequireAcr() throws Exception {
    mvc.perform(get("/api/method").header("Authorization", bearer(person()))).andExpect(status().isOk());
    mvc.perform(get("/api/method").header("Authorization", bearer(person("roles", List.of())))).andExpect(status().isForbidden());
    mvc.perform(get("/api/annotated").header("Authorization", bearer(person())))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.error").value("insufficient_user_authentication"));
    mvc.perform(get("/api/annotated").header("Authorization", bearer(person("acr", AcrRanking.LOA4)))).andExpect(status().isOk());
    var result =
        mvc.perform(get("/api/plain").header("Authorization", bearer(person("roles", Map.of("x", "y"))))).andReturn();
    assertThat(result.getResponse().getStatus()).isEqualTo(401);
  }
}
