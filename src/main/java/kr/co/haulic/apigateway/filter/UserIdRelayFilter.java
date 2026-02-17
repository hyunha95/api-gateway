package kr.co.haulic.apigateway.filter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Authorization Bearer JWT에서 sub claim을 추출하여
 * X-User-Id 헤더로 하위 서비스에 전달하는 글로벌 필터.
 *
 * - JWS 토큰(3파트): payload base64 디코딩으로 sub 추출 (네트워크 호출 없음)
 * - JWE 토큰(5파트): Auth0 /userinfo 엔드포인트를 통해 sub 추출 (결과 캐싱)
 */
@Component
public class UserIdRelayFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(UserIdRelayFilter.class);
    private static final String USER_ID_HEADER = "X-User-Id";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final long CACHE_TTL_MS = 5 * 60 * 1000L; // 5분

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final WebClient webClient;
    private final String userInfoEndpoint;
    private final Map<String, CacheEntry> userIdCache = new ConcurrentHashMap<>();

    public UserIdRelayFilter(@Value("${auth.issuer}") String issuer) {
        this.webClient = WebClient.builder().build();
        this.userInfoEndpoint = issuer.endsWith("/") ? issuer + "userinfo" : issuer + "/userinfo";
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            return chain.filter(exchange);
        }

        String token = authHeader.substring(BEARER_PREFIX.length());
        String[] parts = token.split("\\.");

        // JWS 토큰 (header.payload.signature) — base64 디코딩
        if (parts.length == 3) {
            String userId = extractSubjectFromJws(parts);
            if (userId != null) {
                return chainWithUserId(exchange, chain, userId);
            }
            return chain.filter(exchange);
        }

        // JWE 토큰 또는 기타 — /userinfo 엔드포인트 호출 (캐싱 적용)
        CacheEntry cached = userIdCache.get(token);
        if (cached != null && !cached.isExpired()) {
            return chainWithUserId(exchange, chain, cached.userId);
        }

        return fetchUserIdFromUserInfo(authHeader)
                .doOnNext(userId -> userIdCache.put(token, new CacheEntry(userId)))
                .map(userId -> {
                    ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                            .header(USER_ID_HEADER, userId)
                            .build();
                    log.debug("Relaying X-User-Id={} to downstream service (via /userinfo)", userId);
                    return exchange.mutate().request(mutatedRequest).build();
                })
                .defaultIfEmpty(exchange)
                .flatMap(chain::filter)
                .onErrorResume(e -> {
                    log.warn("Failed to fetch userId from /userinfo: {}", e.getMessage());
                    return chain.filter(exchange);
                });
    }

    private Mono<Void> chainWithUserId(ServerWebExchange exchange, GatewayFilterChain chain, String userId) {
        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header(USER_ID_HEADER, userId)
                .build();
        log.debug("Relaying X-User-Id={} to downstream service", userId);
        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    private String extractSubjectFromJws(String[] parts) {
        try {
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
            JsonNode claims = objectMapper.readTree(payload);
            JsonNode sub = claims.get("sub");

            if (sub == null || sub.isNull()) {
                log.debug("JWS does not contain 'sub' claim");
                return null;
            }

            return sub.asText();
        } catch (Exception e) {
            log.debug("Failed to extract sub from JWS: {}", e.getMessage());
            return null;
        }
    }

    private Mono<String> fetchUserIdFromUserInfo(String authorizationHeader) {
        return webClient.get()
                .uri(userInfoEndpoint)
                .header(HttpHeaders.AUTHORIZATION, authorizationHeader)
                .retrieve()
                .bodyToMono(JsonNode.class)
                .mapNotNull(json -> {
                    JsonNode sub = json.get("sub");
                    return (sub != null && !sub.isNull()) ? sub.asText() : null;
                });
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 1;
    }

    private record CacheEntry(String userId, long createdAt) {
        CacheEntry(String userId) {
            this(userId, System.currentTimeMillis());
        }

        boolean isExpired() {
            return System.currentTimeMillis() - createdAt > CACHE_TTL_MS;
        }
    }
}
