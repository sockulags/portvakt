package se.portvakt.spring;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import se.portvakt.spring.web.HttpRequests;

/** The TypeScript SDK's returnTo and navigation tests. */
class HttpRequestsTest {
  @ParameterizedTest
  @CsvSource({"/,/", "/cases/42?tab=docs#top,/cases/42?tab=docs#top", "/a/../b,/b", "/a/./b/,/a/b/"})
  void acceptsSameOriginPaths(String input, String output) {
    assertThat(HttpRequests.safeReturnTo(input)).isEqualTo(output);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "//evil.example",
        "/\\evil.example",
        "\\\\evil.example",
        "/%2F%2Fevil.example",
        "/%5Cevil.example",
        "https://evil.example/",
        "http:/evil.example",
        "javascript:alert(1)",
        "evil.example",
        "",
        "/\tevil",
        "/a\nb",
        " /a",
        "/%E0%A4%A",
        "/.//evil.com",
        "/a/..//evil.com",
        "/%2e//evil.com",
        "/%2e%2e//evil.com",
        "/%2E//evil.com",
        "/a/b/../..//evil.com",
        "/./%2F/evil.com",
        "/%2e/%5Cevil.com",
        "/a b"
      })
  void refusesEverythingElse(String input) {
    assertThat(HttpRequests.safeReturnTo(input)).isNull();
  }

  @Test
  void refusesLongValuesAndNull() {
    assertThat(HttpRequests.safeReturnTo("/" + "a".repeat(3000))).isNull();
    assertThat(HttpRequests.safeReturnTo(null)).isNull();
  }

  @Test
  void tellsBrowserNavigationsFromXhr() {
    MockHttpServletRequest navigation = new MockHttpServletRequest("GET", "/x");
    navigation.addHeader("Sec-Fetch-Mode", "navigate");
    assertThat(HttpRequests.isBrowserNavigation(navigation)).isTrue();
    MockHttpServletRequest fetch = new MockHttpServletRequest("GET", "/x");
    fetch.addHeader("Sec-Fetch-Mode", "cors");
    fetch.addHeader("Accept", "text/html");
    assertThat(HttpRequests.isBrowserNavigation(fetch)).isFalse();
    MockHttpServletRequest html = new MockHttpServletRequest("GET", "/x");
    html.addHeader("Accept", "text/html,application/xhtml+xml");
    assertThat(HttpRequests.isBrowserNavigation(html)).isTrue();
    html.addHeader("X-Requested-With", "XMLHttpRequest");
    assertThat(HttpRequests.isBrowserNavigation(html)).isFalse();
    MockHttpServletRequest post = new MockHttpServletRequest("POST", "/x");
    post.addHeader("Accept", "text/html");
    assertThat(HttpRequests.isBrowserNavigation(post)).isFalse();
  }

  @Test
  void returnsToTheCurrentPageOnlyForNavigations() {
    MockHttpServletRequest navigation = new MockHttpServletRequest("GET", "/cases/7");
    navigation.setQueryString("tab=docs");
    navigation.addHeader("Sec-Fetch-Mode", "navigate");
    assertThat(HttpRequests.returnToOf(navigation, "/")).isEqualTo("/cases/7?tab=docs");
    MockHttpServletRequest xhr = new MockHttpServletRequest("GET", "/api/cases");
    xhr.addHeader("Accept", "application/json");
    assertThat(HttpRequests.returnToOf(xhr, "/")).isEqualTo("/");
  }
}
