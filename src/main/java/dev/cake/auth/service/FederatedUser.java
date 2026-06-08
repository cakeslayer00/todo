package dev.cake.auth.service;

import dev.cake.auth.entity.AuthProvider;

public record FederatedUser(AuthProvider provider,
                            String subject,
                            String email,
                            boolean emailVerified) {
}
