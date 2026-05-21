package dev.cake.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Schema(description = "New user registration details")
public record RegistrationRequest(
        @NotBlank @Size(min = 3, max = 64)
        @Schema(description = "Desired username", example = "john_doe")
        String username,

        @NotBlank @Email @Size(max = 320)
        @Schema(description = "Email address", example = "john@example.com")
        String email,

        @NotBlank @Size(min = 8, max = 128)
        @Schema(description = "Password (min 8 characters)", example = "securePassword123")
        String password
) {
}
