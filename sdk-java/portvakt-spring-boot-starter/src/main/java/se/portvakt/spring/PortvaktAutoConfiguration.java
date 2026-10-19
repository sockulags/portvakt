package se.portvakt.spring;

import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.AnyNestedCondition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ConditionalOnDefaultWebSecurity;
import org.springframework.boot.security.autoconfigure.web.servlet.SecurityFilterProperties;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientAutoConfiguration;
import org.springframework.boot.security.oauth2.client.autoconfigure.servlet.OAuth2ClientWebSecurityAutoConfiguration;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.web.OAuth2ResourceServerWebSecurityAutoConfiguration;
import org.springframework.context.SmartLifecycle;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.endpoint.NimbusJwtClientAuthenticationParametersConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.RestClientRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.ClassUtils;
import org.springframework.web.client.RestClient;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import se.portvakt.sdk.ClientAuth;
import se.portvakt.sdk.ClientCredentialsTokenProvider;
import se.portvakt.sdk.PortvaktClient;
import se.portvakt.sdk.PortvaktConfig;
import se.portvakt.sdk.PortvaktConfigException;
import se.portvakt.sdk.PortvaktTokenVerifier;
import se.portvakt.spring.login.DeadlineInterceptor;
import se.portvakt.spring.login.InMemoryTokenStore;
import se.portvakt.spring.login.JdbcTokenStore;
import se.portvakt.spring.login.PortvaktAccessTokens;
import se.portvakt.spring.login.PortvaktAuthorizationRequestRepository;
import se.portvakt.spring.login.PortvaktAuthorizationRequestResolver;
import se.portvakt.spring.login.PortvaktAuthorizedClientManager;
import se.portvakt.spring.login.PortvaktAuthorizedClientRepository;
import se.portvakt.spring.login.PortvaktClientRegistrationRepository;
import se.portvakt.spring.login.PortvaktIdTokenDecoderFactory;
import se.portvakt.spring.login.PortvaktLoginComponents;
import se.portvakt.spring.login.PortvaktLoginFailureHandler;
import se.portvakt.spring.login.PortvaktLoginResponses;
import se.portvakt.spring.login.PortvaktLoginSettings;
import se.portvakt.spring.login.PortvaktLoginSuccessHandler;
import se.portvakt.spring.login.PortvaktLogoutSuccessHandler;
import se.portvakt.spring.login.PortvaktOidcUserService;
import se.portvakt.spring.login.PortvaktRefreshTokenProvider;
import se.portvakt.spring.login.PortvaktSessions;
import se.portvakt.spring.login.PortvaktTokenEndpointErrors;
import se.portvakt.spring.login.PortvaktTokenStore;
import se.portvakt.spring.login.TokenSealer;
import se.portvakt.spring.resource.PortvaktBearerErrorHandler;
import se.portvakt.spring.resource.PortvaktBearerTokenResolver;
import se.portvakt.spring.resource.PortvaktJwtAuthenticationConverter;
import se.portvakt.spring.resource.PortvaktJwtDecoder;
import se.portvakt.spring.resource.PortvaktResourceServerComponents;
import se.portvakt.spring.web.PortvaktExceptionResolver;
import se.portvakt.spring.web.RequireAcrInterceptor;

/**
 * Portvakt for Spring Boot 4 (servlet). Active when {@code portvakt.issuer} or one of the modes
 * is set; each mode is enabled on its own:
 *
 * <ul>
 *   <li>{@code portvakt.login.enabled}: browser login (oauth2Login, server-side session, tokens in
 *       the token store);
 *   <li>{@code portvakt.resource-server.enabled}: access token validation for the API;
 *   <li>{@code portvakt.client-credentials.enabled}: a {@link ClientCredentialsTokenProvider}.
 * </ul>
 *
 * Without a {@code SecurityFilterChain} of the application's own, it adds a resource server
 * chain ({@code portvakt.resource-server.paths}, first) and a login chain (everything else:
 * {@code portvakt.login.public-paths} open, the rest requires a login). Applications with their
 * own chains apply {@link PortvaktSecurity#login()} and {@link PortvaktSecurity#resourceServer()}.
 * It runs before Spring Boot's security auto-configurations (so they back off) and after the
 * DataSource auto-configuration (the JDBC token store).
 */
@AutoConfiguration(
    before = {
      SecurityAutoConfiguration.class,
      ServletWebSecurityAutoConfiguration.class,
      UserDetailsServiceAutoConfiguration.class,
      OAuth2ClientAutoConfiguration.class,
      OAuth2ClientWebSecurityAutoConfiguration.class,
      OAuth2ResourceServerAutoConfiguration.class,
      OAuth2ResourceServerWebSecurityAutoConfiguration.class
    },
    afterName = PortvaktAutoConfiguration.DATA_SOURCE_AUTO_CONFIGURATION)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@Conditional(PortvaktAutoConfiguration.PortvaktConfigured.class)
@EnableConfigurationProperties(PortvaktProperties.class)
public class PortvaktAutoConfiguration {
  private static final Logger LOG = LoggerFactory.getLogger(PortvaktAutoConfiguration.class);

  /** Boot's DataSource auto-configuration (spring-boot-jdbc, optional). */
  static final String DATA_SOURCE_AUTO_CONFIGURATION =
      "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration";

  /** Spring Session's filter: its sessions are snapshots written back by each request. */
  static final String SESSION_REPOSITORY_FILTER = "org.springframework.session.web.http.SessionRepositoryFilter";

  /** Any of {@code portvakt.issuer} and the {@code *.enabled} flags. */
  static class PortvaktConfigured extends AnyNestedCondition {
    PortvaktConfigured() {
      super(ConfigurationPhase.REGISTER_BEAN);
    }

    @ConditionalOnProperty(prefix = "portvakt", name = "issuer")
    static class Issuer {}

    @ConditionalOnProperty(prefix = "portvakt.login", name = "enabled", havingValue = "true")
    static class Login {}

    @ConditionalOnProperty(prefix = "portvakt.resource-server", name = "enabled", havingValue = "true")
    static class ResourceServer {}

    @ConditionalOnProperty(prefix = "portvakt.client-credentials", name = "enabled", havingValue = "true")
    static class ClientCredentials {}
  }

  /** The clock of token times and session ends; replace it in tests. */
  @Bean
  @ConditionalOnMissingBean(name = "portvaktClock")
  Clock portvaktClock() {
    return Clock.systemUTC();
  }

  @Bean
  @ConditionalOnMissingBean
  PortvaktClient portvaktClient(PortvaktProperties properties, @Qualifier("portvaktClock") Clock clock) {
    PortvaktConfig config = PortvaktPropertiesMapper.config(properties, clock);
    return PortvaktClient.create(config);
  }

  @Bean
  @ConditionalOnMissingBean
  PortvaktTokenVerifier portvaktTokenVerifier(PortvaktClient client) {
    return client.verifier();
  }

  @Bean(name = "portvakt")
  @ConditionalOnMissingBean
  PortvaktSecurity portvaktSecurity(PortvaktClient client, PortvaktProperties properties) {
    return new PortvaktSecurity(
        client.verifier(),
        client.config().acrRanking(),
        properties.getResourceServer().isEnabled() ? PortvaktPropertiesMapper.resourceDefaults(properties) : null);
  }

  // Browser login --------------------------------------------------------------------------------

  @Configuration(proxyBeanMethods = false)
  @ConditionalOnProperty(prefix = "portvakt.login", name = "enabled", havingValue = "true")
  static class LoginConfiguration {
    @Bean
    PortvaktLoginSettings portvaktLoginSettings(PortvaktProperties properties) {
      return PortvaktPropertiesMapper.loginSettings(properties);
    }

    @Bean
    @ConditionalOnMissingBean(ClientRegistrationRepository.class)
    PortvaktClientRegistrationRepository portvaktClientRegistrationRepository(
        PortvaktClient client, PortvaktLoginSettings settings) {
      return new PortvaktClientRegistrationRepository(client.config(), client.discovery(), settings);
    }

    /** Where the sessions' tokens live: memory (default) or JDBC. */
    @Bean
    @ConditionalOnMissingBean(PortvaktTokenStore.class)
    PortvaktTokenStore portvaktTokenStore(
        PortvaktProperties properties,
        ObjectProvider<DataSource> dataSources,
        PortvaktClient client,
        @Qualifier("portvaktClock") Clock clock,
        Environment environment) {
      PortvaktProperties.Login login = properties.getLogin();
      if (login.getTokenStore() == PortvaktProperties.TokenStore.JDBC) {
        DataSource dataSource = dataSources.getIfUnique();
        if (dataSource == null) {
          throw new PortvaktConfigException(
              java.util.List.of("portvakt.login.token-store: jdbc needs exactly one DataSource bean"));
        }
        JdbcTokenStore store =
            new JdbcTokenStore(
                dataSource,
                new TokenSealer(login.getTokenEncryptionKey()),
                clock,
                client.config().httpTimeout().plusSeconds(5),
                login.getTokenStoreTable());
        if (login.isTokenStoreInitializeSchema()) store.initializeSchema();
        return store;
      }
      if (environment.acceptsProfiles(Profiles.of("prod | production"))) {
        LOG.warn(
            "portvakt.login.token-store=memory in a production profile: tokens are lost on restart and"
                + " not shared between instances; use token-store=jdbc for more than one instance");
      }
      return new InMemoryTokenStore(clock);
    }

    /** Warns at start about an insecure session cookie in a production profile. */
    @Bean
    SmartInitializingSingleton portvaktCookieCheck(Environment environment) {
      return () -> {
        for (String warning : se.portvakt.spring.login.PortvaktCookieCheck.warnings(environment)) LOG.warn(warning);
      };
    }

    /** Deletes expired tokens and pending logins in the background. */
    @Bean
    SmartLifecycle portvaktTokenStoreCleanup(PortvaktTokenStore store, PortvaktProperties properties) {
      return new TokenStoreCleanup(store, properties.getLogin().getTokenStoreCleanupInterval());
    }

    /**
     * Spring Session writes each request's session snapshot back: with tokens in memory of one
     * instance that is only correct on a single instance, so it must be allowed explicitly.
     */
    @Bean
    SmartInitializingSingleton portvaktSpringSessionGuard(
        ListableBeanFactory beans, PortvaktTokenStore store, PortvaktProperties properties) {
      return () -> {
        if (!(store instanceof InMemoryTokenStore)
            || properties.getLogin().isAllowInMemoryTokenStoreWithSpringSession()
            || !ClassUtils.isPresent(SESSION_REPOSITORY_FILTER, beans.getClass().getClassLoader())) {
          return;
        }
        Class<?> filter = ClassUtils.resolveClassName(SESSION_REPOSITORY_FILTER, beans.getClass().getClassLoader());
        if (beans.getBeanNamesForType(filter, true, false).length > 0) {
          throw new PortvaktConfigException(
              java.util.List.of(
                  "portvakt.login.token-store: Spring Session is in use; set token-store=jdbc (or"
                      + " allow-in-memory-token-store-with-spring-session=true for one instance)"));
        }
      };
    }

    @Bean
    PortvaktSessions portvaktSessions(
        PortvaktTokenStore store, PortvaktLoginSettings settings, @Qualifier("portvaktClock") Clock clock) {
      return new PortvaktSessions(store, settings, clock);
    }

    /** Tokens live in the token store; the HTTP session holds only the grant id. */
    @Bean
    @ConditionalOnMissingBean(OAuth2AuthorizedClientRepository.class)
    OAuth2AuthorizedClientRepository portvaktAuthorizedClientRepository(
        PortvaktTokenStore store,
        ClientRegistrationRepository registrations,
        PortvaktLoginSettings settings,
        @Qualifier("portvaktClock") Clock clock) {
      return new PortvaktAuthorizedClientRepository(store, registrations, settings, clock);
    }

    @Bean
    PortvaktAuthorizationRequestRepository portvaktAuthorizationRequestRepository(
        PortvaktTokenStore store, @Qualifier("portvaktClock") Clock clock) {
      return new PortvaktAuthorizationRequestRepository(store, clock);
    }

    /** ID tokens of oauth2Login are validated by the core verifier. */
    @Bean
    @ConditionalOnMissingBean
    JwtDecoderFactory<ClientRegistration> portvaktIdTokenDecoderFactory(PortvaktTokenVerifier verifier) {
      return new PortvaktIdTokenDecoderFactory(verifier);
    }

    @Bean
    PortvaktTokenEndpoint portvaktTokenEndpoint(PortvaktClient client) {
      return new PortvaktTokenEndpoint(client.config());
    }

    @Bean
    @ConditionalOnMissingBean
    OAuth2AuthorizedClientManager portvaktAuthorizedClientManager(
        ClientRegistrationRepository registrations,
        PortvaktTokenStore store,
        PortvaktTokenEndpoint tokens,
        PortvaktClient client,
        @Qualifier("portvaktClock") Clock clock) {
      Duration minValidity = client.config().clockSkew().plusSeconds(30);
      return new PortvaktAuthorizedClientManager(
          registrations, store, new PortvaktRefreshTokenProvider(tokens.refreshTokenClient(), minValidity, clock));
    }

    @Bean
    @ConditionalOnMissingBean
    PortvaktAccessTokens portvaktAccessTokens(
        OAuth2AuthorizedClientManager manager, PortvaktTokenVerifier verifier, PortvaktSessions sessions) {
      return new PortvaktAccessTokens(manager, verifier, sessions);
    }

    @Bean
    PortvaktLoginResponses portvaktLoginResponses(PortvaktLoginSettings settings) {
      return new PortvaktLoginResponses(settings);
    }

    @Bean
    @ConditionalOnMissingBean
    PortvaktLoginComponents portvaktLoginComponents(
        PortvaktLoginSettings settings,
        ClientRegistrationRepository registrations,
        OAuth2AuthorizedClientRepository authorizedClients,
        PortvaktAuthorizationRequestRepository authorizationRequests,
        PortvaktTokenEndpoint tokens,
        PortvaktLoginResponses responses,
        PortvaktSessions sessions,
        PortvaktClient client,
        @Qualifier("portvaktClock") Clock clock) {
      return new PortvaktLoginComponents(
          settings,
          registrations,
          authorizedClients,
          authorizationRequests,
          new PortvaktAuthorizationRequestResolver(registrations, settings),
          tokens.authorizationCodeClient(),
          new PortvaktOidcUserService(),
          new PortvaktLoginSuccessHandler(sessions),
          new PortvaktLoginFailureHandler(settings),
          new PortvaktLogoutSuccessHandler(registrations, settings),
          responses,
          sessions,
          client.config().acrRanking(),
          clock);
    }
  }

  /** Runs {@link PortvaktTokenStore#deleteExpired()} periodically on a daemon thread. */
  static final class TokenStoreCleanup implements SmartLifecycle {
    private final PortvaktTokenStore store;
    private final Duration interval;
    private java.util.concurrent.ScheduledExecutorService executor;

    TokenStoreCleanup(PortvaktTokenStore store, Duration interval) {
      this.store = store;
      this.interval = interval;
    }

    @Override
    public synchronized void start() {
      executor =
          java.util.concurrent.Executors.newSingleThreadScheduledExecutor(
              runnable -> Thread.ofPlatform().daemon(true).name("portvakt-token-store-cleanup").unstarted(runnable));
      long millis = Math.max(1000, interval.toMillis());
      executor.scheduleWithFixedDelay(
          () -> {
            try {
              store.deleteExpired();
            } catch (RuntimeException failed) {
              LOG.warn("token store cleanup failed: {}", failed.getClass().getSimpleName());
            }
          },
          millis,
          millis,
          java.util.concurrent.TimeUnit.MILLISECONDS);
    }

    @Override
    public synchronized void stop() {
      if (executor != null) executor.shutdownNow();
      executor = null;
    }

    @Override
    public synchronized boolean isRunning() {
      return executor != null;
    }
  }

  /**
   * The token endpoint clients of the login (code exchange, refresh): Spring's RestClient clients
   * with one deadline for the whole request ({@code portvakt.http-timeout}), no redirects, OAuth
   * errors read from 400 and 401 answers, and the configured client authentication
   * (private_key_jwt through Spring's Nimbus converter).
   */
  public static final class PortvaktTokenEndpoint {
    private final RestClientAuthorizationCodeTokenResponseClient codeClient;
    private final RestClientRefreshTokenTokenResponseClient refreshClient;

    PortvaktTokenEndpoint(PortvaktConfig config) {
      HttpClient http =
          HttpClient.newBuilder()
              .connectTimeout(config.httpTimeout())
              .followRedirects(HttpClient.Redirect.NEVER)
              .build();
      JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(http);
      factory.setReadTimeout(config.httpTimeout());
      RestClient rest =
          RestClient.builder()
              .requestFactory(factory)
              .requestInterceptor(new DeadlineInterceptor(config.httpTimeout()))
              .messageConverters(
                  converters -> {
                    converters.clear();
                    converters.add(new FormHttpMessageConverter());
                    converters.add(new OAuth2AccessTokenResponseHttpMessageConverter());
                  })
              .defaultStatusHandler(new PortvaktTokenEndpointErrors())
              .build();
      codeClient = new RestClientAuthorizationCodeTokenResponseClient();
      codeClient.setRestClient(rest);
      refreshClient = new RestClientRefreshTokenTokenResponseClient();
      refreshClient.setRestClient(rest);
      if (config.clientAuth() instanceof ClientAuth.PrivateKeyJwt key) {
        codeClient.addParametersConverter(
            new NimbusJwtClientAuthenticationParametersConverter<OAuth2AuthorizationCodeGrantRequest>(
                registration -> key.privateJwk()));
        refreshClient.addParametersConverter(
            new NimbusJwtClientAuthenticationParametersConverter<OAuth2RefreshTokenGrantRequest>(
                registration -> key.privateJwk()));
      }
    }

    public RestClientAuthorizationCodeTokenResponseClient authorizationCodeClient() {
      return codeClient;
    }

    public RestClientRefreshTokenTokenResponseClient refreshTokenClient() {
      return refreshClient;
    }
  }

  // Resource server ------------------------------------------------------------------------------

  @Configuration(proxyBeanMethods = false)
  @ConditionalOnProperty(prefix = "portvakt.resource-server", name = "enabled", havingValue = "true")
  static class ResourceServerConfiguration {
    @Bean
    @ConditionalOnMissingBean(JwtDecoder.class)
    PortvaktJwtDecoder portvaktJwtDecoder(PortvaktTokenVerifier verifier, PortvaktProperties properties) {
      return new PortvaktJwtDecoder(verifier, PortvaktPropertiesMapper.resourceDefaults(properties).audience());
    }

    @Bean
    @ConditionalOnMissingBean
    PortvaktResourceServerComponents portvaktResourceServerComponents(
        PortvaktJwtDecoder decoder, PortvaktProperties properties) {
      return new PortvaktResourceServerComponents(
          decoder,
          new PortvaktJwtAuthenticationConverter(PortvaktPropertiesMapper.resourceDefaults(properties)),
          new PortvaktBearerTokenResolver(),
          new PortvaktBearerErrorHandler());
    }
  }

  // Service-to-service ---------------------------------------------------------------------------

  @Configuration(proxyBeanMethods = false)
  @ConditionalOnProperty(prefix = "portvakt.client-credentials", name = "enabled", havingValue = "true")
  static class ClientCredentialsConfiguration {
    @Bean
    @ConditionalOnMissingBean
    ClientCredentialsTokenProvider portvaktClientCredentials(PortvaktClient client) {
      return client.clientCredentials();
    }
  }

  // Spring MVC: @RequireAcr and SDK errors -------------------------------------------------------

  @Configuration(proxyBeanMethods = false)
  static class MvcConfiguration implements WebMvcConfigurer {
    private final PortvaktSecurity security;
    private final ObjectProvider<PortvaktLoginResponses> login;

    MvcConfiguration(PortvaktSecurity security, ObjectProvider<PortvaktLoginResponses> login) {
      this.security = security;
      this.login = login;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
      registry.addInterceptor(new RequireAcrInterceptor(security, login.getIfAvailable()));
    }

    @Bean
    HandlerExceptionResolver portvaktExceptionResolver(ObjectProvider<PortvaktLoginResponses> responses) {
      return new PortvaktExceptionResolver(responses.getIfAvailable());
    }
  }

  // Default filter chains ------------------------------------------------------------------------

  @Configuration(proxyBeanMethods = false)
  @ConditionalOnDefaultWebSecurity
  static class DefaultSecurityFilterChains {
    @Bean
    @Order(SecurityFilterProperties.BASIC_AUTH_ORDER - 10)
    @ConditionalOnProperty(prefix = "portvakt.resource-server", name = "enabled", havingValue = "true")
    SecurityFilterChain portvaktResourceServerFilterChain(
        HttpSecurity http, PortvaktProperties properties, PortvaktSecurity portvakt) {
      http.securityMatcher(PortvaktPropertiesMapper.resourcePaths(properties).toArray(String[]::new));
      http.with(PortvaktSecurity.resourceServer(), Customizer.withDefaults());
      http.authorizeHttpRequests(requests -> requests.anyRequest().access(portvakt.accessToken()));
      return http.build();
    }

    @Bean
    @Order(SecurityFilterProperties.BASIC_AUTH_ORDER - 5)
    @ConditionalOnProperty(prefix = "portvakt.login", name = "enabled", havingValue = "true")
    SecurityFilterChain portvaktLoginFilterChain(HttpSecurity http, PortvaktLoginSettings settings) {
      http.with(PortvaktSecurity.login(), Customizer.withDefaults());
      http.authorizeHttpRequests(
          requests -> {
            if (!settings.publicPaths().isEmpty()) {
              requests.requestMatchers(settings.publicPaths().toArray(String[]::new)).permitAll();
            }
            requests.anyRequest().authenticated();
          });
      return http.build();
    }
  }
}
