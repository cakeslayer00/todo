package dev.cake.auth.sociallogin;

import dev.cake.auth.identity.AuthProvider;

public record FederatedUser(AuthProvider provider,
                            String subject,
                            String email,
                            boolean emailVerified) {
}
