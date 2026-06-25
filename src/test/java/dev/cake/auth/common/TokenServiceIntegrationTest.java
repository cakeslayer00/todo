package dev.cake.auth.common;

import dev.cake.auth.common.properties.JwtTokenProperties;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
public class TokenServiceIntegrationTest extends AbstractIntegrationTest {

    @Autowired
    JwtTokenProperties tokenProperties;
    @Autowired
    TokenService tokenService;
    @Autowired
    JwtDecoder jwtDecoder;

    @Test
    void generated_token_carries_subject_issuer_and_one_hour_expiry() {
        var subject = UUID.randomUUID().toString();

        String token = tokenService.generateToken(subject);
        Jwt decoded = jwtDecoder.decode(token);

        assertThat(decoded.getSubject()).isEqualTo(subject);
        assertThat(decoded.getIssuer()).hasToString("https://cakeslayer.dev");
        assertThat(decoded.getIssuedAt()).isNotNull();
        assertThat(decoded.getExpiresAt()).isNotNull();
        assertThat(ChronoUnit.SECONDS.between(decoded.getIssuedAt(), decoded.getExpiresAt()))
                .isEqualTo(tokenProperties.expiry().getSeconds());
    }
}
