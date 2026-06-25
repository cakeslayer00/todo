package dev.cake.auth.emailverification.event;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.UUID;

public record EmailVerificationRequested(@JsonProperty("public_id") UUID publicId,
                                         String username,
                                         String email,
                                         String token) {
}
