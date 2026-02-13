package kr.co.haulic.apigateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

/**
 * API Gateway CORS 설정 (Java Config)
 *
 * Spring Cloud Gateway는 Reactive WebFlux 기반이므로
 * CorsWebFilter를 사용하여 CORS를 처리합니다.
 */
@Configuration
public class CorsConfig {

    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration corsConfig = new CorsConfiguration();

        // allowCredentials=true일 때는 allowedOriginPatterns 사용
        corsConfig.setAllowedOriginPatterns(Arrays.asList(
            "http://localhost:3000",  // haulic-cms-frontend & chunwon-market
            "http://localhost:3001"   // chunwon-market (alternative port)
        ));

        // 허용된 HTTP 메서드
        corsConfig.setAllowedMethods(Arrays.asList(
            "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"
        ));

        // 허용된 헤더
        corsConfig.setAllowedHeaders(List.of("*"));

        // 노출할 헤더 (클라이언트에서 접근 가능한 헤더)
        corsConfig.setExposedHeaders(Arrays.asList(
            "Authorization", "Content-Type", "Location"
        ));

        // 자격 증명(쿠키, 인증 헤더) 허용
        corsConfig.setAllowCredentials(true);

        // Preflight 요청 캐시 시간 (초)
        corsConfig.setMaxAge(3600L);

        // 모든 경로에 대해 CORS 설정 적용
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);

        return new CorsWebFilter(source);
    }
}
