package dev.cake.auth.authentication.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Authentication response with JWT token")
public record AuthResponse(
        @Schema(description = "JWT access token", example = "eyJhbGciOiJSUzI1NiJ9...")
        String accessToken,

        @Schema(description = "Authenticated username", example = "john_doe")
        String username
) {
}
