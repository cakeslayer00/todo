package dev.cake.auth.registration.event;

import java.util.UUID;

/**
 * Raised in-process once a local user has been persisted. Other features
 * (e.g. email verification) react to it instead of registration calling them
 * directly, so registration stays unaware of what happens next.
 */
public record UserRegisteredEvent(UUID publicId) {
}
