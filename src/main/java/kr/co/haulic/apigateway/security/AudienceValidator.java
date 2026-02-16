package kr.co.haulic.apigateway.security;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Objects;

/**
 * JWT 'aud' claim에 특정 audience가 포함되어 있는지 검증.
 * Auth0 access token의 aud는 배열일 수 있으므로 contains로 판별.
 */
public class AudienceValidator implements OAuth2TokenValidator<Jwt> {

    private final String audience;

    public AudienceValidator(String audience) {
        this.audience = Objects.requireNonNull(audience, "audience must not be null");
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        Objects.requireNonNull(jwt, "jwt must not be null");

        if (jwt.getAudience() != null && jwt.getAudience().contains(audience)) {
            return OAuth2TokenValidatorResult.success();
        }

        OAuth2Error error = new OAuth2Error(
                "invalid_token",
                String.format("The required audience '%s' is missing", audience),
                null
        );
        return OAuth2TokenValidatorResult.failure(error);
    }
}
