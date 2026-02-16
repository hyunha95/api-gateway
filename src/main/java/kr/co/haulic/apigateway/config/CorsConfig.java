package kr.co.haulic.apigateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

/**
 * CORS 설정.
 *
 * CorsConfigurationSource 빈을 노출하여 Spring Security의
 * {@code http.cors(Customizer.withDefaults())}가 자동으로 픽업하도록 한다.
 * (별도 CorsWebFilter 빈은 불필요 – Security 체인 내부에서 CORS를 처리)
 */
@Configuration
public class CorsConfig {

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfig = new CorsConfiguration();

        corsConfig.setAllowedOriginPatterns(Arrays.asList(
                "http://localhost:3000",
                "http://localhost:3001"
        ));

        corsConfig.setAllowedMethods(Arrays.asList(
                "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"
        ));

        corsConfig.setAllowedHeaders(List.of("*"));

        corsConfig.setExposedHeaders(Arrays.asList(
                "Authorization", "Content-Type", "Location"
        ));

        corsConfig.setAllowCredentials(true);
        corsConfig.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);
        return source;
    }
}
