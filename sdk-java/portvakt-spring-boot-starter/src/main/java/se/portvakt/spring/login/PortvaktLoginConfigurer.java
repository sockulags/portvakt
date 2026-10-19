package se.portvakt.spring.login;

import java.util.ArrayList;
import java.util.List;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.boot.security.autoconfigure.web.servlet.PathRequest;

/**
 * Applies the Portvakt browser login to an {@link HttpSecurity}: oauth2Login against the tenant
 * issuer (PKCE, ID token validated by the core, no userinfo), the login routes below {@code
 * portvakt.login.base-path}, step-up and representation switch, tokens and pending logins in the
 * token store (never in the HTTP session), session end at {@code session_exp} and after the idle
 * timeout, RP-initiated logout ({@code POST {base}/logout}), {@code GET {base}/session} and
 * structured 401/403 answers. Authorization rules stay the application's:
 *
 * <pre>{@code
 * http.with(PortvaktSecurity.login(), Customizer.withDefaults())
 *     .authorizeHttpRequests(a -> a.requestMatchers("/").permitAll().anyRequest().authenticated());
 * }</pre>
 *
 * {@code portvakt.login.public-paths} also say which requests are no activity for the idle
 * timeout. Keep Spring Security's default session fixation protection ({@code changeSessionId}).
 */
public class PortvaktLoginConfigurer extends AbstractHttpConfigurer<PortvaktLoginConfigurer, HttpSecurity> {
  @Override
  public void init(HttpSecurity http) {
    PortvaktLoginComponents components = components(http);
    PortvaktLoginSettings settings = components.settings();
    http.oauth2Login(
        login ->
            login
                .clientRegistrationRepository(components.registrations())
                .authorizedClientRepository(components.authorizedClients())
                .loginPage(settings.loginPath())
                .loginProcessingUrl(settings.callbackPath())
                .authorizationEndpoint(
                    endpoint ->
                        endpoint
                            .authorizationRequestResolver(components.resolver())
                            .authorizationRequestRepository(components.authorizationRequests()))
                .tokenEndpoint(endpoint -> endpoint.accessTokenResponseClient(components.codeTokenClient()))
                .userInfoEndpoint(endpoint -> endpoint.oidcUserService(components.userService()))
                .authenticationDetailsSource(PortvaktLoginDetails::new)
                .successHandler(components.successHandler())
                .failureHandler(components.failureHandler())
                .withObjectPostProcessor(
                    new ObjectPostProcessor<OAuth2LoginAuthenticationFilter>() {
                      @Override
                      public <O extends OAuth2LoginAuthenticationFilter> O postProcess(O filter) {
                        AuthenticationManager manager = http.getSharedObject(AuthenticationManager.class);
                        filter.setAuthenticationManager(
                            new PortvaktLoginAuthenticationManager(manager, components.ranking(), components.clock()));
                        return filter;
                      }
                    })
                .withObjectPostProcessor(
                    new ObjectPostProcessor<OAuth2AuthorizationRequestRedirectFilter>() {
                      @Override
                      public <O extends OAuth2AuthorizationRequestRedirectFilter> O postProcess(O filter) {
                        filter.setAuthenticationFailureHandler(components.failureHandler());
                        return filter;
                      }
                    }));
    http.logout(
        logout ->
            logout
                .logoutRequestMatcher(
                    PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, settings.logoutPath()))
                .addLogoutHandler(
                    (request, response, authentication) -> {
                      PortvaktSessionState state = PortvaktSessionState.of(request.getSession(false));
                      if (state != null && state.grantId() != null) components.sessions().store().delete(state.grantId());
                    })
                .logoutSuccessHandler(components.logoutSuccessHandler())
                .invalidateHttpSession(true)
                .clearAuthentication(true));
    http.exceptionHandling(
        exceptions ->
            exceptions
                .authenticationEntryPoint(new PortvaktAuthenticationEntryPoint(components.responses()))
                .accessDeniedHandler(new PortvaktAccessDeniedHandler(components.responses())));
  }

  @Override
  public void configure(HttpSecurity http) {
    PortvaktLoginComponents components = components(http);
    http.addFilterAfter(
        new PortvaktSessionExpiryFilter(components.sessions(), notActivity(components.settings())),
        SecurityContextHolderFilter.class);
    http.addFilterAfter(new PortvaktSessionInfoFilter(components.settings()), CsrfFilter.class);
  }

  /** Requests that are no activity: login routes, the session JSON, public paths, static files. */
  static RequestMatcher notActivity(PortvaktLoginSettings settings) {
    PathPatternRequestMatcher.Builder paths = PathPatternRequestMatcher.withDefaults();
    List<RequestMatcher> matchers = new ArrayList<>();
    matchers.add(paths.matcher(settings.basePath() + "/**"));
    for (String path : settings.publicPaths()) matchers.add(paths.matcher(path));
    matchers.add(PathRequest.toStaticResources().atCommonLocations());
    return new OrRequestMatcher(matchers);
  }

  private static PortvaktLoginComponents components(HttpSecurity http) {
    ApplicationContext context = http.getSharedObject(ApplicationContext.class);
    return context.getBean(PortvaktLoginComponents.class);
  }
}
