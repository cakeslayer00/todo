package dev.cake.auth.common.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.boot.convert.DurationUnit;

import java.time.Duration;
import java.time.temporal.ChronoUnit;

@ConfigurationProperties("app.jwt.meta")
public record JwtTokenProperties(String issuer,
                                 @DefaultValue("15") @DurationUnit(ChronoUnit.MINUTES) Duration expiry) {
}
