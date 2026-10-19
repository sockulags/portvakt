package se.portvakt.demo;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

/** The demo without a Portvakt: it starts (Portvakt is contacted lazily) and serves its pages. */
@SpringBootTest(properties = "portvakt.issuer=http://localhost:9/t/demo")
@AutoConfigureMockMvc
@ActiveProfiles("local")
class DemoApplicationTest {
  @Autowired MockMvc mvc;

  @Test
  void answersHealthChecksAndTheSignedOutPage() throws Exception {
    mvc.perform(get("/healthz"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.status").value("ok"))
        .andExpect(jsonPath("$.app").value("Tjänst C"))
        .andExpect(header().string("Content-Security-Policy", org.hamcrest.Matchers.containsString("form-action 'self' http://localhost:9")))
        .andExpect(header().string("Content-Security-Policy", org.hamcrest.Matchers.containsString("frame-ancestors 'none'")))
        .andExpect(header().string("X-Frame-Options", "DENY"))
        .andExpect(header().string("X-Content-Type-Options", "nosniff"))
        .andExpect(header().string("Cross-Origin-Opener-Policy", "same-origin"))
        .andExpect(header().string("Permissions-Policy", org.hamcrest.Matchers.containsString("camera=()")));
    String page =
        mvc.perform(get("/").accept("text/html")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
    assertThat(page).contains("data-testid=\"signed-out-view\"").contains("data-testid=\"sign-in\"");
    assertThat(page).contains("/auth/login?returnTo=%2F");
  }

  @Test
  void servesTheDesignSystemTokensWithoutTheRemoteFontImport() throws Exception {
    String tokens = mvc.perform(get("/css/tokens.css")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
    assertThat(tokens).contains("--color-bg").doesNotContain("fonts.googleapis.com");
  }

  @Test
  void protectsItsRoutesAndApi() throws Exception {
    mvc.perform(get("/app/api-call").accept("application/json"))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.error").value("login_required"));
    mvc.perform(get("/api/whoami"))
        .andExpect(status().isUnauthorized())
        .andExpect(header().string("WWW-Authenticate", "Bearer realm=\"portvakt\""));
    // Portvakt unreachable: a login cannot start, with a clear page.
    String page =
        mvc.perform(get("/auth/login").accept("text/html"))
            .andExpect(status().isServiceUnavailable())
            .andReturn()
            .getResponse()
            .getContentAsString();
    assertThat(page).contains("portvakt_unavailable").contains("Inloggningstjänsten är inte tillgänglig just nu");
  }
}
