package kr.co.haulic.apigateway.security;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;

/**
 * Gateway Security 설정 – Shop / CMS 경로별 SecurityWebFilterChain 분리.
 *
 * <ul>
 *   <li>CMS  chain (@Order 1) : /api/cms/**  – audience + Auth0 RBAC permissions 인가</li>
 *   <li>Shop chain (@Order 2) : /api/shop/** – audience 인증 (일부 공개 엔드포인트)</li>
 *   <li>Default chain (@Order 3) : 그 외 – actuator permitAll, 기존 라우트 issuer-only JWT 인증</li>
 * </ul>
 *
 * CORS는 각 체인에 {@code cors(Customizer.withDefaults())}를 적용하여
 * Security 필터 내부에서 처리한다 (CorsConfigurationSource 빈 자동 픽업).
 */
@Configuration
@EnableWebFluxSecurity
public class GatewaySecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(GatewaySecurityConfig.class);

    @Value("${auth.issuer}")
    private String issuer;

    @Value("${auth.audience.shop}")
    private String shopAudience;

    @Value("${auth.audience.cms}")
    private String cmsAudience;

    @PostConstruct
    void validateProperties() {
        requireNonBlank(issuer, "auth.issuer");
        requireNonBlank(shopAudience, "auth.audience.shop");
        requireNonBlank(cmsAudience, "auth.audience.cms");
        log.info("Gateway security configured – issuer={}, shopAud={}, cmsAud={}",
                issuer, shopAudience, cmsAudience);
    }

    // ================================================================
    //  CMS Security Chain – /api/cms/**
    // ================================================================

    @Bean
    @Order(1)
    public SecurityWebFilterChain cmsSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .securityMatcher(new PathPatternParserServerWebExchangeMatcher("/api/cms/**"))
                .cors(Customizer.withDefaults())
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(ex -> ex
                        .pathMatchers("/api/cms/health").permitAll()
                        .pathMatchers(HttpMethod.GET, "/api/cms/**").hasAuthority("PERM_cms:read")
                        .pathMatchers(HttpMethod.POST, "/api/cms/**").hasAuthority("PERM_cms:write")
                        .pathMatchers(HttpMethod.PUT, "/api/cms/**").hasAuthority("PERM_cms:write")
                        .pathMatchers(HttpMethod.PATCH, "/api/cms/**").hasAuthority("PERM_cms:write")
                        .pathMatchers(HttpMethod.DELETE, "/api/cms/**").hasAuthority("PERM_cms:write")
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .jwtDecoder(buildJwtDecoder(cmsAudience))
                                .jwtAuthenticationConverter(jwtAuthenticationConverter())
                        )
                )
                .build();
    }

    // ================================================================
    //  Shop Security Chain – /api/shop/**
    // ================================================================

    @Bean
    @Order(2)
    public SecurityWebFilterChain shopSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .securityMatcher(new PathPatternParserServerWebExchangeMatcher("/api/shop/**"))
                .cors(Customizer.withDefaults())
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(ex -> ex
                        .pathMatchers("/api/shop/products/**").permitAll()
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .jwtDecoder(buildJwtDecoder(shopAudience))
                                .jwtAuthenticationConverter(jwtAuthenticationConverter())
                        )
                )
                .build();
    }

    // ================================================================
    //  Default Chain – actuator, 기존 라우트(/api/admin/** 등)
    //  레거시 라우트는 /api/cms/**, /api/shop/** 전환 완료 후 제거 예정.
    //  전환 전까지 permitAll – 개별 서비스 레벨 인증에 위임.
    // ================================================================

    @Bean
    @Order(3)
    public SecurityWebFilterChain defaultSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .cors(Customizer.withDefaults())
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(ex -> ex
                        .anyExchange().permitAll()
                )
                .build();
    }

    // ----------------------------------------------------------------
    //  JWT Decoder – issuer + audience 검증 (CMS / Shop 체인용)
    // ----------------------------------------------------------------

    private ReactiveJwtDecoder buildJwtDecoder(String audience) {
        NimbusReactiveJwtDecoder decoder = (NimbusReactiveJwtDecoder)
                ReactiveJwtDecoders.fromIssuerLocation(issuer);

        OAuth2TokenValidator<Jwt> withIssuer =
                JwtValidators.createDefaultWithIssuer(issuer);
        OAuth2TokenValidator<Jwt> withAudience =
                new AudienceValidator(audience);
        OAuth2TokenValidator<Jwt> combined =
                new DelegatingOAuth2TokenValidator<>(withIssuer, withAudience);

        decoder.setJwtValidator(combined);
        return decoder;
    }

    // ----------------------------------------------------------------
    //  JWT → Authentication 변환 (permissions + scope → GrantedAuthority)
    // ----------------------------------------------------------------

    private ReactiveJwtAuthenticationConverterAdapter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new Auth0PermissionsConverter());
        return new ReactiveJwtAuthenticationConverterAdapter(converter);
    }

    private static void requireNonBlank(String value, String propertyName) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(
                    "Required property '" + propertyName + "' is not configured or is blank");
        }
    }
}
