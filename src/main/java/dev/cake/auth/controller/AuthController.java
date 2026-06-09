package dev.cake.auth.controller;

import dev.cake.auth.dto.AuthRequest;
import dev.cake.auth.dto.AuthResponse;
import dev.cake.auth.dto.RegistrationRequest;
import dev.cake.auth.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication")
public class AuthController {

    private final AuthService authService;

    @PostMapping
    @Operation(summary = "Authenticate user", description = "Validates credentials and returns a JWT access token")
    @SecurityRequirements
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Successfully authenticated",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))),
            @ApiResponse(responseCode = "400", description = "Invalid credentials",
                    content = @Content(schema = @Schema(implementation = ProblemDetail.class))),
    })
    public ResponseEntity<AuthResponse> authenticate(@RequestBody @Valid AuthRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/register")
    @Operation(summary = "Register a new user", description = "Creates a new user account and returns 201 Created")
    @SecurityRequirements
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "User successfully registered"),
            @ApiResponse(responseCode = "409", description = "Username or email already taken",
                    content = @Content(schema = @Schema(implementation = ProblemDetail.class))),
            @ApiResponse(responseCode = "400", description = "Validation error",
                    content = @Content(schema = @Schema(implementation = ProblemDetail.class)))
    })
    public ResponseEntity<Void> register(@RequestBody @Valid RegistrationRequest request) {
        authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/verify")
    @Operation(summary = "Verify email address",
            description = "Consumes a verification token from the emailed link and marks the user's email as verified")
    @SecurityRequirements
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Email successfully verified"),
            @ApiResponse(responseCode = "400", description = "Token is invalid, expired, or already used",
                    content = @Content(schema = @Schema(implementation = ProblemDetail.class)))
    })
    public ResponseEntity<Void> verify(@RequestParam("token") String token) {
        authService.verifyConfirmationToken(token);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/verify/resend")
    @Operation(summary = "Resend verification email",
            description = "Re-issues a verification link for the authenticated, not-yet-verified user. "
                    + "Any previously issued links are invalidated.")
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "A fresh verification link has been queued for delivery"),
            @ApiResponse(responseCode = "400", description = "Email is already verified",
                    content = @Content(schema = @Schema(implementation = ProblemDetail.class))),
            @ApiResponse(responseCode = "401", description = "Missing or invalid access token",
                    content = @Content(schema = @Schema(implementation = ProblemDetail.class)))
    })
    public ResponseEntity<Void> resendVerification(@AuthenticationPrincipal Jwt jwt) {
        authService.resendVerification(UUID.fromString(jwt.getSubject()));
        return ResponseEntity.accepted().build();
    }

}
