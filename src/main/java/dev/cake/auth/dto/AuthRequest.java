package dev.cake.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Schema(description = "Login credentials")
public record AuthRequest(
        @NotBlank @Size(min = 3, max = 64)
        @Schema(description = "Username", example = "john_doe")
        String username,

        @NotBlank @Size(min = 8, max = 128)
        @Schema(description = "Password", example = "securePassword123")
        String password
) {
}
