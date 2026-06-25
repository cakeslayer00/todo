package dev.cake.auth.emailverification;

import dev.cake.auth.common.AbstractIntegrationTest;
import dev.cake.auth.common.exception.InvalidTokenException;
import dev.cake.auth.emailverification.event.EmailVerificationRequested;
import dev.cake.auth.identity.User;
import dev.cake.auth.identity.UserRepository;
import dev.cake.auth.registration.event.UserRegisteredEvent;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.event.ApplicationEvents;
import org.springframework.test.context.event.RecordApplicationEvents;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Transactional
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
@RecordApplicationEvents
public class EmailVerificationIntegrationTest extends AbstractIntegrationTest {

    @Autowired
    UserRepository userRepository;
    @Autowired
    EmailVerificationRepository emailVerificationRepository;
    @Autowired
    EmailVerificationService emailVerificationService;
    @Autowired
    EmailVerificationTokenService emailVerificationTokenService;
    @Autowired
    EmailVerificationTokenProperties emailVerificationTokenProperties;
    @Autowired
    ApplicationEventPublisher applicationEventPublisher;
    @Autowired
    ApplicationEvents applicationEvents;
    @Autowired
    JdbcTemplate jdbcTemplate;
    @PersistenceContext
    EntityManager entityManager;

    @Test
    void when_invalid_token_received_throw_exception() {
        assertThatThrownBy(() -> emailVerificationService.verify("randomstring")).isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void when_expired_token_received_throw_exception() {
        var user = generatePersistedUser();

        var verification = issueVerificationTokenAndGetVerification(user);
        verification.emailVerification().setExpiresAt(Instant.now());

        assertThatThrownBy(() -> emailVerificationService.verify(verification.rawToken))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void when_consumed_token_received_throw_exception() {
        var user = generatePersistedUser();

        var verification = issueVerificationTokenAndGetVerification(user);
        verification.emailVerification().setConsumedAt(Instant.now());

        assertThatThrownBy(() -> emailVerificationService.verify(verification.rawToken))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void when_valid_token_received_email_verified() {
        var user = generatePersistedUser();

        var token = issueVerificationToken(user);
        emailVerificationService.verify(token);

        var hash = emailVerificationTokenService.hash(token);
        Optional<EmailVerification> optEV = emailVerificationRepository.findByTokenHash(hash);

        assertThat(optEV).isPresent();
        assertThat(optEV.get().getConsumedAt()).isBefore(Instant.now());
        assertThat(optEV.get().getUser().isEmailVerified()).isTrue();
    }

    @Test
    void when_user_registered_event_published_email_verification_event_emitted() {
        var user = generatePersistedUser();

        applicationEventPublisher.publishEvent(new UserRegisteredEvent(user.getPublicId()));

        assertThat(applicationEvents.stream(EmailVerificationRequested.class))
                .singleElement()
                .extracting(EmailVerificationRequested::publicId)
                .isEqualTo(user.getPublicId());
    }

    @Test
    void when_user_registered_event_emitted_outbox_row_is_written() {
        var user = generatePersistedUser();

        applicationEventPublisher.publishEvent(new UserRegisteredEvent(user.getPublicId()));
        // Force the outbox INSERT onto the shared transactional connection so the
        // raw query below can see it (still rolled back at the end of the test).
        entityManager.flush();

        var rows = jdbcTemplate.queryForList(
                "select aggregatetype, aggregateid, type, payload::text as payload from outbox");

        assertThat(rows)
                .singleElement()
                .satisfies(row -> {
                    assertThat(row).containsEntry("aggregatetype", "email_verification");
                    assertThat(row).containsEntry("aggregateid", user.getPublicId().toString());
                    assertThat(row).containsEntry("type", "EmailVerificationRequested");
                    assertThat(row.get("payload").toString())
                            .contains(user.getPublicId().toString())
                            .contains("johndoe")
                            .contains("johndoe@example.com")
                            .contains("token");
                });
    }

    @Test
    void when_resend_invoked_by_missing_user_throws_exception() {
        assertThatThrownBy(() -> emailVerificationService.resendVerificationToken(UUID.randomUUID()))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void when_resend_invoked_by_user_with_verified_email_throws_exception() {
        User user = generatePersistedUser();
        user.setEmailVerified(true);
        userRepository.save(user);

        assertThatThrownBy(() -> emailVerificationService.resendVerificationToken(user.getPublicId()))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void when_resend_invoked_email_verification_event_published() {
        User user = generatePersistedUser();

        emailVerificationService.resendVerificationToken(user.getPublicId());

        assertThat(applicationEvents.stream(EmailVerificationRequested.class))
                .singleElement()
                .extracting(EmailVerificationRequested::publicId)
                .isEqualTo(user.getPublicId());
    }

    private String issueVerificationToken(User user) {
        var generatedToken = emailVerificationTokenService.generate();
        generatePersistedEmailVerification(user, generatedToken.tokenHash());

        return generatedToken.rawToken();
    }

    private VerificationWrapper issueVerificationTokenAndGetVerification(User user) {
        var generatedToken = emailVerificationTokenService.generate();
        var rawToken = generatedToken.rawToken();
        return new VerificationWrapper(rawToken, generatePersistedEmailVerification(user, generatedToken.tokenHash()));
    }

    private @NonNull EmailVerification generatePersistedEmailVerification(User user, String tokenHash) {
        return emailVerificationRepository.save(EmailVerification.builder()
                .user(user)
                .tokenHash(tokenHash)
                .expiresAt(Instant.now().plus(emailVerificationTokenProperties.expiry()))
                .build());
    }

    private @NonNull User generatePersistedUser() {
        return userRepository.saveAndFlush(User.builder()
                .username("johndoe")
                .email("johndoe@example.com")
                .emailVerified(false)
                .build());
    }

    private record VerificationWrapper(String rawToken, EmailVerification emailVerification) {
    }

}
