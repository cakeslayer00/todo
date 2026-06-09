package dev.cake.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.boot.convert.DurationUnit;

import java.time.Duration;
import java.time.temporal.ChronoUnit;

@ConfigurationProperties(prefix = "verification.token")
public record VerificationTokenProperties(
        @DefaultValue("24") @DurationUnit(ChronoUnit.HOURS) Duration expiry) {
}
