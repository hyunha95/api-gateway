package kr.co.haulic.apigateway.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * API Gateway 라우팅 설정
 *
 * - CMS Admin API: /api/admin/** → lb://cms
 * - Product Recommendations: /api/recommendations/** → lb://product
 * - Product Interactions: /api/interactions/** → lb://product
 * - Product Uploads: /uploads/** → lb://product (이미지 서빙)
 */
@Configuration
public class GatewayConfig {

    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                // CMS Admin API 라우팅
                .route("cms-service", r -> r
                        .path("/api/admin/**")
                        .uri("lb://cms"))

                // Product Recommendations API 라우팅
                .route("product-recommendations", r -> r
                        .path("/api/recommendations/**")
                        .uri("lb://product"))

                // Product Interactions API 라우팅
                .route("product-interactions", r -> r
                        .path("/api/interactions/**")
                        .uri("lb://product"))

                // Product 이미지 업로드 파일 서빙
                .route("product-uploads", r -> r
                        .path("/uploads/**")
                        .uri("lb://product"))

                .build();
    }
}
