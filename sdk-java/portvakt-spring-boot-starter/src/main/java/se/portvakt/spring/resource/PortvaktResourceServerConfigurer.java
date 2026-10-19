package se.portvakt.spring.resource;

import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;

/**
 * Applies Portvakt access token validation to an {@link HttpSecurity}: stateless, bearer tokens
 * from the Authorization header only, the core-backed {@link PortvaktJwtDecoder}, {@link
 * PortvaktJwtAuthenticationConverter} and RFC 6750 answers (also 503 when Portvakt's keys cannot
 * be fetched). CSRF is off for this chain (no cookies). Authorization rules stay the
 * application's, for example {@code .anyRequest().access(portvakt.accessToken())}.
 */
public class PortvaktResourceServerConfigurer
    extends AbstractHttpConfigurer<PortvaktResourceServerConfigurer, HttpSecurity> {
  @Override
  public void init(HttpSecurity http) {
    PortvaktResourceServerComponents components =
        http.getSharedObject(org.springframework.context.ApplicationContext.class)
            .getBean(PortvaktResourceServerComponents.class);
    http.oauth2ResourceServer(
        server ->
            server
                .jwt(jwt -> jwt.decoder(components.decoder()).jwtAuthenticationConverter(components.converter()))
                .bearerTokenResolver(components.tokenResolver())
                .authenticationEntryPoint(components.errors())
                .accessDeniedHandler(components.errors())
                .withObjectPostProcessor(
                    new ObjectPostProcessor<BearerTokenAuthenticationFilter>() {
                      @Override
                      public <O extends BearerTokenAuthenticationFilter> O postProcess(O filter) {
                        filter.setAuthenticationFailureHandler(components.errors());
                        return filter;
                      }
                    }));
    http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
    http.csrf(csrf -> csrf.disable());
    http.requestCache(cache -> cache.disable());
    http.exceptionHandling(
        exceptions -> exceptions.authenticationEntryPoint(components.errors()).accessDeniedHandler(components.errors()));
  }
}
