package dev.cake.auth.messaging.event;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.UUID;

public record UserRegisteredEvent(@JsonProperty("public_id") UUID publicId,
                                  String email) {
}
