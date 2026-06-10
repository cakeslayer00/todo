package dev.cake.auth.emailverification;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.boot.convert.DurationUnit;

import java.time.Duration;
import java.time.temporal.ChronoUnit;

@ConfigurationProperties(prefix = "email-verification.token")
record EmailVerificationTokenProperties(
        @DefaultValue("24") @DurationUnit(ChronoUnit.HOURS) Duration expiry) {
}
