package dev.cake.auth.common;

import dev.cake.auth.common.properties.JwtTokenProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final JwtEncoder jwtEncoder;
    private final JwtTokenProperties jwtTokenProperties;

    public String generateToken(String subject) {
        var now = Instant.now();
        var claims = JwtClaimsSet.builder()
                .issuer(jwtTokenProperties.issuer())
                .subject(subject)
                .issuedAt(now)
                .expiresAt(now.plus(jwtTokenProperties.expiry()))
                .build();
        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

}
