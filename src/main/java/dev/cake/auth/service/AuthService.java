package dev.cake.auth.service;

import dev.cake.auth.dto.AuthRequest;
import dev.cake.auth.dto.AuthResponse;
import dev.cake.auth.dto.RegistrationRequest;
import dev.cake.auth.entity.AuthProvider;
import dev.cake.auth.entity.EmailVerification;
import dev.cake.auth.entity.Identity;
import dev.cake.auth.entity.User;
import dev.cake.auth.config.VerificationTokenProperties;
import dev.cake.auth.exception.DuplicateResourceException;
import dev.cake.auth.exception.InvalidTokenException;
import dev.cake.auth.messaging.event.EmailVerificationRequestedEvent;
import dev.cake.auth.repository.EmailVerificationRepository;
import dev.cake.auth.repository.IdentityRepository;
import dev.cake.auth.repository.UserRepository;
import dev.cake.auth.security.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final IdentityRepository identityRepository;
    private final EmailVerificationRepository emailVerificationRepository;

    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    private final TokenService tokenService;

    private final ApplicationEventPublisher eventPublisher;

    private final VerificationTokenService verificationTokenService;
    private final VerificationTokenProperties verificationTokenProperties;

    public AuthResponse login(AuthRequest request) {
        var authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.email(), request.password())
        );

        var token = tokenService.generateToken(String.valueOf(
                ((CustomUserDetails) Objects.requireNonNull(authentication.getPrincipal())).publicId()
        ));
        log.info("User authenticated with username: '{}'", authentication.getName());
        return new AuthResponse(token, authentication.getName());
    }

    @Transactional
    public void register(RegistrationRequest request) {
        if (userRepository.findByEmail(request.email()).isPresent()) {
            throw new DuplicateResourceException("Email", request.email());
        }

        var user = User.builder()
                .username(request.username())
                .email(request.email())
                .emailVerified(false)
                .passwordHash(passwordEncoder.encode(request.password()))
                .build();

        userRepository.saveAndFlush(user);
        log.info("User registered with username: '{}'", user.getUsername());

        var identity = Identity.builder()
                .user(user)
                .provider(AuthProvider.LOCAL)
                .providerSubject(String.valueOf(user.getPublicId()))
                .build();

        identityRepository.save(identity);
        log.info("Local provider identity added to user: '{}'", identity.getProviderSubject());

        var rawToken = issueVerificationToken(user);

        eventPublisher.publishEvent(new EmailVerificationRequestedEvent(
                user.getPublicId(), user.getUsername(), user.getEmail(), rawToken));
        log.info("Published EmailVerificationRequestedEvent for user {} after registration", user.getPublicId());
    }

    @Transactional
    public void resendVerification(UUID publicId) {
        var user = userRepository.findByPublicId(publicId)
                .orElseThrow(() -> new InvalidTokenException("User not found"));

        if (Boolean.TRUE.equals(user.getEmailVerified())) {
            throw new InvalidTokenException("Email already verified");
        }

        emailVerificationRepository.consumeAllActiveForUser(user, Instant.now());
        var rawToken = issueVerificationToken(user);

        eventPublisher.publishEvent(new EmailVerificationRequestedEvent(
                user.getPublicId(), user.getUsername(), user.getEmail(), rawToken));
        log.info("Published EmailVerificationRequestedEvent for user {}", user.getPublicId());
    }

    @Transactional
    public void verifyConfirmationToken(String token) {
        var hash = verificationTokenService.hash(token);
        var verification = emailVerificationRepository.findByTokenHash(hash)
                .orElseThrow(() -> new InvalidTokenException("Invalid verification token"));

        if (verification.getConsumedAt() != null) {
            throw new InvalidTokenException("Token already used");
        }
        if (verification.getExpiresAt().isBefore(Instant.now())) {
            throw new InvalidTokenException("Token expired");
        }

        verification.setConsumedAt(Instant.now());
        verification.getUser().setEmailVerified(true);
    }

    private String issueVerificationToken(User user) {
        var verificationToken = verificationTokenService.generate();
        emailVerificationRepository.save(EmailVerification.builder()
                .user(user)
                .tokenHash(verificationToken.tokenHash())
                .expiresAt(Instant.now().plus(verificationTokenProperties.expiry()))
                .build());

        log.info("Verification code for user {} is generated", user.getPublicId());
        return verificationToken.rawToken();
    }

}
