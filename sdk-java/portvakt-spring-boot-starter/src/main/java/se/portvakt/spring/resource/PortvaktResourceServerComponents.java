package se.portvakt.spring.resource;

/**
 * Everything {@link PortvaktResourceServerConfigurer} wires into Spring Security's resource
 * server, as one bean.
 *
 * @param decoder the core-backed JWT decoder
 * @param converter the principal and authorities
 * @param tokenResolver the Authorization header only
 * @param errors RFC 6750 answers
 */
public record PortvaktResourceServerComponents(
    PortvaktJwtDecoder decoder,
    PortvaktJwtAuthenticationConverter converter,
    PortvaktBearerTokenResolver tokenResolver,
    PortvaktBearerErrorHandler errors) {}
