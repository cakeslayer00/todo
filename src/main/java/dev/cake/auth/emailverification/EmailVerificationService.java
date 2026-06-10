package dev.cake.auth.emailverification;

import dev.cake.auth.identity.User;
import dev.cake.auth.common.exception.InvalidTokenException;
import dev.cake.auth.emailverification.event.EmailVerificationRequestedEvent;
import dev.cake.auth.identity.UserRepository;
import dev.cake.auth.registration.event.UserRegisteredEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
class EmailVerificationService {

    private final UserRepository userRepository;
    private final EmailVerificationRepository emailVerificationRepository;
    private final EmailVerificationTokenService emailVerificationTokenService;

    private final ApplicationEventPublisher applicationEventPublisher;
    private final EmailVerificationTokenProperties emailVerificationTokenProperties;

    @Transactional
    void verify(String token) {
        var hash = emailVerificationTokenService.hash(token);
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
        log.info("User verified successfully!:)");
    }

    /**
     * Issues the first verification link as part of registration. Runs synchronously
     * inside the registration transaction, so the token is persisted atomically with
     * the new user — if anything here fails, the registration rolls back too.
     */
    @EventListener
    void onUserRegistered(UserRegisteredEvent event) {
        var user = userRepository.findByPublicId(event.publicId())
                .orElseThrow(() -> new InvalidTokenException("User not found"));
        issueAndPublish(user);
    }

    @Transactional
    void resendVerificationToken(UUID userPublicId) {
        var user = userRepository.findByPublicId(userPublicId)
                .orElseThrow(() -> new InvalidTokenException("User not found"));

        if (Boolean.TRUE.equals(user.getEmailVerified())) {
            throw new InvalidTokenException("Email already verified");
        }

        emailVerificationRepository.consumeAllActiveForUser(user, Instant.now());
        issueAndPublish(user);
    }

    private void issueAndPublish(User user) {
        var rawToken = issueVerificationToken(user);

        applicationEventPublisher.publishEvent(new EmailVerificationRequestedEvent(
                user.getPublicId(), user.getUsername(), user.getEmail(), rawToken));
        log.info("EmailVerificationRequestedEvent was emitted for kafka producer");
    }

    private String issueVerificationToken(User user) {
        var generatedToken = emailVerificationTokenService.generate();
        emailVerificationRepository.save(EmailVerification.builder()
                .user(user)
                .tokenHash(generatedToken.tokenHash())
                .expiresAt(Instant.now().plus(emailVerificationTokenProperties.expiry()))
                .build());

        log.info("Email verification code for user {} is generated", user.getPublicId());
        return generatedToken.rawToken();
    }

}
