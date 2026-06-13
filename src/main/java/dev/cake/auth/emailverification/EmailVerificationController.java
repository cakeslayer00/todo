package dev.cake.auth.emailverification;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.persistence.Table;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth/verify")
@RequiredArgsConstructor
@Tag(name = "Email Verification")
class EmailVerificationController {

    private final EmailVerificationService emailVerificationService;

    @PostMapping
    @Operation(summary = "Verify email address",
            description = "Consumes a verification token from the emailed link and marks the user's email as verified")
    @SecurityRequirements
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Email successfully verified"),
            @ApiResponse(responseCode = "400", description = "Token is invalid, expired, or already used",
                    content = @Content(schema = @Schema(implementation = ProblemDetail.class)))
    })
    public ResponseEntity<Void> verify(@RequestParam("token") String token) {
        emailVerificationService.verify(token);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/resend")
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
    public ResponseEntity<Void> resend(@AuthenticationPrincipal Jwt jwt) {

        emailVerificationService.resendVerificationToken(UUID.fromString(jwt.getSubject()));
        return ResponseEntity.accepted().build();
    }

}
