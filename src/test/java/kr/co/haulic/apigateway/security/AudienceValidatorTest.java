package kr.co.haulic.apigateway.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AudienceValidatorTest {

    private static final String REQUIRED = "https://api.yourdomain.com/shop";
    private final AudienceValidator validator = new AudienceValidator(REQUIRED);

    @Test
    void successWhenAudienceContainsRequiredValue() {
        Jwt jwt = jwt(List.of(REQUIRED, "https://other.com"));
        OAuth2TokenValidatorResult result = validator.validate(jwt);

        assertThat(result.hasErrors()).isFalse();
    }

    @Test
    void failWhenAudienceDoesNotContainRequiredValue() {
        Jwt jwt = jwt(List.of("https://wrong.com"));
        OAuth2TokenValidatorResult result = validator.validate(jwt);

        assertThat(result.hasErrors()).isTrue();
        assertThat(result.getErrors())
                .anyMatch(e -> e.getDescription().contains(REQUIRED));
    }

    @Test
    void failWhenAudienceIsEmpty() {
        Jwt jwt = jwt(List.of());
        OAuth2TokenValidatorResult result = validator.validate(jwt);

        assertThat(result.hasErrors()).isTrue();
    }

    @Test
    void constructorRejectsNullAudience() {
        assertThatThrownBy(() -> new AudienceValidator(null))
                .isInstanceOf(NullPointerException.class);
    }

    private static Jwt jwt(List<String> audiences) {
        return new Jwt(
                "token-value",
                Instant.now(),
                Instant.now().plusSeconds(3600),
                Map.of("alg", "RS256"),
                Map.of("aud", audiences, "sub", "user1")
        );
    }
}
