package se.portvakt.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.http.converter.autoconfigure.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration;
import org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientAutoConfiguration;
import org.springframework.boot.security.oauth2.client.autoconfigure.servlet.OAuth2ClientWebSecurityAutoConfiguration;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.web.OAuth2ResourceServerWebSecurityAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.webmvc.autoconfigure.DispatcherServletAutoConfiguration;
import org.springframework.boot.webmvc.autoconfigure.WebMvcAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.web.http.SessionRepositoryFilter;
import se.portvakt.sdk.ClientCredentialsTokenProvider;
import se.portvakt.sdk.PortvaktClient;
import se.portvakt.sdk.PortvaktConfigException;
import se.portvakt.spring.login.InMemoryTokenStore;
import se.portvakt.spring.login.JdbcTokenStore;
import se.portvakt.spring.login.PortvaktAccessTokens;
import se.portvakt.spring.login.PortvaktAuthorizedClientManager;
import se.portvakt.spring.login.PortvaktAuthorizedClientRepository;
import se.portvakt.spring.login.PortvaktClientRegistrationRepository;
import se.portvakt.spring.login.PortvaktTokenStore;
import se.portvakt.spring.resource.PortvaktJwtDecoder;

class PortvaktAutoConfigurationTest {
  static final String SECRET = "a-client-secret-0123456789abcdef";
  static final String KEY = java.util.Base64.getEncoder().encodeToString(new byte[32]);

  final WebApplicationContextRunner base =
      new WebApplicationContextRunner()
          .withConfiguration(
              AutoConfigurations.of(
                  PortvaktAutoConfiguration.class,
                  SecurityAutoConfiguration.class,
                  ServletWebSecurityAutoConfiguration.class,
                  UserDetailsServiceAutoConfiguration.class,
                  OAuth2ClientAutoConfiguration.class,
                  OAuth2ClientWebSecurityAutoConfiguration.class,
                  OAuth2ResourceServerAutoConfiguration.class,
                  OAuth2ResourceServerWebSecurityAutoConfiguration.class,
                  WebMvcAutoConfiguration.class,
                  DispatcherServletAutoConfiguration.class,
                  HttpMessageConvertersAutoConfiguration.class,
                  JacksonAutoConfiguration.class));

  final WebApplicationContextRunner runner =
      base.withPropertyValues(
          "portvakt.issuer=https://login.example.org/t/kommunen", "portvakt.client-id=case-service");

  @Test
  void ordersItselfBeforeBootsSecurityAndAfterTheDataSourceWithClassesThatExist() throws Exception {
    AutoConfiguration ordering = PortvaktAutoConfiguration.class.getAnnotation(AutoConfiguration.class);
    List<String> before = new ArrayList<>(Arrays.stream(ordering.before()).map(Class::getName).toList());
    before.addAll(List.of(ordering.beforeName()));
    assertThat(before)
        .contains(
            SecurityAutoConfiguration.class.getName(),
            ServletWebSecurityAutoConfiguration.class.getName(),
            UserDetailsServiceAutoConfiguration.class.getName(),
            OAuth2ClientAutoConfiguration.class.getName(),
            OAuth2ClientWebSecurityAutoConfiguration.class.getName(),
            OAuth2ResourceServerAutoConfiguration.class.getName(),
            OAuth2ResourceServerWebSecurityAutoConfiguration.class.getName());
    List<String> after = new ArrayList<>(List.of(ordering.afterName()));
    after.addAll(Arrays.stream(ordering.after()).map(Class::getName).toList());
    assertThat(after).contains("org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration");
    // Every name must resolve: a misspelt ordering name is silently ignored by Spring Boot.
    for (String name : before) assertThat(Class.forName(name)).isNotNull();
    for (String name : after) assertThat(Class.forName(name)).isNotNull();
    // And Boot's security backs off for the starter's chains in a full context (below).
  }

  @Test
  void staysOffWithoutPortvaktProperties() {
    new WebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(PortvaktAutoConfiguration.class))
        .run(context -> assertThat(context).doesNotHaveBean(PortvaktClient.class));
  }

  @Test
  void providesTheCoreWithoutAnyModeAndLeavesSecurityToBoot() {
    runner.run(
        context -> {
          assertThat(context).hasNotFailed().hasSingleBean(PortvaktClient.class).hasBean("portvakt");
          assertThat(context).doesNotHaveBean(ClientRegistrationRepository.class);
          assertThat(context).doesNotHaveBean(JwtDecoder.class);
          assertThat(context).doesNotHaveBean("portvaktLoginFilterChain");
        });
  }

  @Test
  void enablesTheBrowserLoginWithTokensOutsideTheSession() {
    runner
        .withPropertyValues("portvakt.client-secret=" + SECRET, "portvakt.login.enabled=true")
        .run(
            context -> {
              assertThat(context).hasNotFailed();
              assertThat(context.getBean(ClientRegistrationRepository.class)).isInstanceOf(PortvaktClientRegistrationRepository.class);
              assertThat(context.getBean(OAuth2AuthorizedClientRepository.class))
                  .isInstanceOf(PortvaktAuthorizedClientRepository.class);
              assertThat(context.getBean(OAuth2AuthorizedClientManager.class)).isInstanceOf(PortvaktAuthorizedClientManager.class);
              assertThat(context.getBean(PortvaktTokenStore.class)).isInstanceOf(InMemoryTokenStore.class);
              assertThat(context).hasSingleBean(PortvaktAccessTokens.class);
              // Boot's own chain and generated user back off for the starter's chain.
              assertThat(context).hasBean("portvaktLoginFilterChain").doesNotHaveBean("defaultSecurityFilterChain");
              assertThat(context).doesNotHaveBean("portvaktResourceServerFilterChain");
              assertThat(context).doesNotHaveBean(InMemoryUserDetailsManager.class);
              assertThat(context).doesNotHaveBean(ClientCredentialsTokenProvider.class);
            });
  }

  @Configuration(proxyBeanMethods = false)
  static class SpringSession {
    @Bean
    SessionRepositoryFilter<?> springSessionRepositoryFilter() {
      return new SessionRepositoryFilter<>(new MapSessionRepository(new java.util.concurrent.ConcurrentHashMap<>()));
    }
  }

  @Configuration(proxyBeanMethods = false)
  static class Database {
    @Bean
    javax.sql.DataSource dataSource() {
      return new org.postgresql.ds.PGSimpleDataSource();
    }
  }

  @Test
  void refusesTheInMemoryTokenStoreWithSpringSessionUnlessAllowed() {
    WebApplicationContextRunner login =
        runner.withUserConfiguration(SpringSession.class).withPropertyValues("portvakt.client-secret=" + SECRET, "portvakt.login.enabled=true");
    login.run(
        context -> {
          assertThat(context).hasFailed();
          assertThat(context.getStartupFailure()).hasStackTraceContaining("Spring Session is in use");
        });
    login
        .withPropertyValues("portvakt.login.allow-in-memory-token-store-with-spring-session=true")
        .run(context -> assertThat(context).hasNotFailed());
    login
        .withUserConfiguration(Database.class)
        .withPropertyValues("portvakt.login.token-store=jdbc", "portvakt.login.token-encryption-key=" + KEY)
        .run(
            context -> {
              assertThat(context).hasNotFailed();
              assertThat(context.getBean(PortvaktTokenStore.class)).isInstanceOf(JdbcTokenStore.class);
            });
  }

  @Test
  void requiresADataSourceAndAnEncryptionKeyForTheJdbcTokenStore() {
    WebApplicationContextRunner jdbc =
        runner.withPropertyValues(
            "portvakt.client-secret=" + SECRET, "portvakt.login.enabled=true", "portvakt.login.token-store=jdbc");
    jdbc.run(context -> assertThat(context.getStartupFailure()).hasStackTraceContaining("needs exactly one DataSource"));
    jdbc.withUserConfiguration(Database.class)
        .run(context -> assertThat(context.getStartupFailure()).hasStackTraceContaining("token-encryption-key: required"));
    jdbc.withUserConfiguration(Database.class)
        .withPropertyValues("portvakt.login.token-encryption-key=c2hvcnQ=")
        .run(context -> assertThat(context.getStartupFailure()).hasStackTraceContaining("each key must be 32 bytes"));
  }

  @Test
  void enablesTheResourceServerOnItsOwnWithTheClientIdAsAudience() {
    runner
        .withPropertyValues("portvakt.resource-server.enabled=true")
        .run(
            context -> {
              assertThat(context).hasNotFailed();
              assertThat(context.getBean(JwtDecoder.class)).isInstanceOf(PortvaktJwtDecoder.class);
              assertThat(((PortvaktJwtDecoder) context.getBean(JwtDecoder.class)).audience()).isEqualTo("case-service");
              assertThat(context).hasBean("portvaktResourceServerFilterChain");
              assertThat(context).doesNotHaveBean("portvaktLoginFilterChain");
              assertThat(context).doesNotHaveBean(ClientRegistrationRepository.class);
            });
  }

  @Test
  void enablesBothModesAndServiceTokens() {
    runner
        .withPropertyValues(
            "portvakt.client-secret=" + SECRET,
            "portvakt.login.enabled=true",
            "portvakt.resource-server.enabled=true",
            "portvakt.resource-server.audience=case-api",
            "portvakt.client-credentials.enabled=true")
        .run(
            context -> {
              assertThat(context).hasNotFailed();
              assertThat(context).hasBean("portvaktLoginFilterChain").hasBean("portvaktResourceServerFilterChain");
              assertThat(context).hasSingleBean(ClientCredentialsTokenProvider.class);
              assertThat(((PortvaktJwtDecoder) context.getBean(JwtDecoder.class)).audience()).isEqualTo("case-api");
            });
  }

  @Test
  void refusesAnInvalidConfigurationListingThePropertiesWithoutValues() {
    runner
        .withPropertyValues(
            "portvakt.issuer=http://login.example.org/t/kommunen/",
            "portvakt.client-secret=short-secret",
            "portvakt.login.enabled=true",
            "portvakt.login.redirect-uri=https://case.example.org/wrong",
            "portvakt.login.default-return-to=https://evil.example/")
        .run(
            context -> {
              assertThat(context).hasFailed();
              Throwable failure = context.getStartupFailure();
              while (failure != null && !(failure instanceof PortvaktConfigException)) failure = failure.getCause();
              assertThat(failure).isInstanceOf(PortvaktConfigException.class);
              assertThat(((PortvaktConfigException) failure).issues())
                  .contains("portvakt.client-secret: at least 16 characters")
                  .anyMatch(issue -> issue.startsWith("portvakt.issuer: must be https"))
                  .anyMatch(issue -> issue.startsWith("portvakt.issuer: must be the issuer exactly"))
                  .anyMatch(issue -> issue.startsWith("portvakt.login.redirect-uri: must point at the login callback"))
                  .anyMatch(issue -> issue.startsWith("portvakt.login.default-return-to"));
              assertThat(failure.getMessage()).doesNotContain("short-secret");
            });
  }

  @Test
  void requiresAClientSecretForTheLoginAndAnIssuerForAnyMode() {
    runner
        .withPropertyValues("portvakt.login.enabled=true")
        .run(
            context -> {
              assertThat(context).hasFailed();
              assertThat(context.getStartupFailure()).hasStackTraceContaining("required for the login");
            });
    base.withPropertyValues("portvakt.resource-server.enabled=true")
        .run(context -> assertThat(context.getStartupFailure()).hasStackTraceContaining("portvakt.issuer: required"));
  }

  @Configuration(proxyBeanMethods = false)
  static class OwnChain {
    @Bean
    SecurityFilterChain ownChain(HttpSecurity http) {
      http.with(PortvaktSecurity.login(), chain -> {});
      http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated());
      return http.build();
    }
  }

  @Test
  void backsOffItsDefaultChainsForTheApplicationsOwn() {
    runner
        .withUserConfiguration(OwnChain.class)
        .withPropertyValues("portvakt.client-secret=" + SECRET, "portvakt.login.enabled=true")
        .run(
            context -> {
              assertThat(context).hasNotFailed().hasBean("ownChain");
              assertThat(context).doesNotHaveBean("portvaktLoginFilterChain");
            });
  }

  @Test
  void warnsAboutAnInsecureSessionCookieInAProductionProfile() {
    org.springframework.mock.env.MockEnvironment production = new org.springframework.mock.env.MockEnvironment();
    production.setActiveProfiles("prod");
    assertThat(se.portvakt.spring.login.PortvaktCookieCheck.warnings(production))
        .hasSize(2)
        .anySatisfy(warning -> assertThat(warning).startsWith("server.servlet.session.cookie.secure is not true"))
        .anySatisfy(warning -> assertThat(warning).startsWith("server.servlet.session.cookie.same-site is not set"));
    production.setProperty("server.servlet.session.cookie.secure", "true");
    production.setProperty("server.servlet.session.cookie.same-site", "lax");
    assertThat(se.portvakt.spring.login.PortvaktCookieCheck.warnings(production)).isEmpty();
    // Outside a production profile nothing is said (local http development).
    assertThat(se.portvakt.spring.login.PortvaktCookieCheck.warnings(new org.springframework.mock.env.MockEnvironment()))
        .isEmpty();
    runner
        .withPropertyValues("portvakt.client-secret=" + SECRET, "portvakt.login.enabled=true")
        .run(context -> assertThat(context).hasNotFailed().hasBean("portvaktCookieCheck"));
  }
}
