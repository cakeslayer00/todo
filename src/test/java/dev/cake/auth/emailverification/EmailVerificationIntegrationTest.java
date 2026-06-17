package dev.cake.auth.emailverification;

import dev.cake.auth.common.AbstractIntegrationTest;
import dev.cake.auth.common.exception.InvalidTokenException;
import dev.cake.auth.emailverification.event.EmailVerificationRequestedEvent;
import dev.cake.auth.identity.User;
import dev.cake.auth.identity.UserRepository;
import dev.cake.auth.messaging.configuration.KafkaTopicProperties;
import dev.cake.auth.registration.event.UserRegisteredEvent;
import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.support.serializer.JacksonJsonDeserializer;
import org.springframework.kafka.test.EmbeddedKafkaBroker;
import org.springframework.kafka.test.utils.KafkaTestUtils;
import org.springframework.test.context.event.ApplicationEvents;
import org.springframework.test.context.event.RecordApplicationEvents;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;
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
    EmbeddedKafkaBroker embeddedKafkaBroker;
    @Autowired
    KafkaTopicProperties kafkaTopicProperties;
    @Autowired
    TransactionTemplate txTemplate;

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

        assertThat(applicationEvents.stream(EmailVerificationRequestedEvent.class))
                .singleElement()
                .extracting(EmailVerificationRequestedEvent::publicId)
                .isEqualTo(user.getPublicId());
    }

    @Test
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    void when_user_registered_event_emitted_verification_event_is_published_and_consumed_from_kafka() {
        try (Consumer<String, EmailVerificationRequestedEvent> consumer = createTestConsumer()) {
            embeddedKafkaBroker.consumeFromAnEmbeddedTopic(consumer, kafkaTopicProperties.emailVerificationRequested().name());

            var user = generatePersistedUser();

            txTemplate.executeWithoutResult(_ -> {
                applicationEventPublisher.publishEvent(new UserRegisteredEvent(user.getPublicId()));
            });

            ConsumerRecord<String, EmailVerificationRequestedEvent> record =
                    KafkaTestUtils.getSingleRecord(consumer, kafkaTopicProperties.emailVerificationRequested().name(), Duration.ofSeconds(10));

            assertThat(record.key()).isEqualTo(user.getPublicId().toString());
            assertThat(record.value().publicId()).isEqualTo(user.getPublicId());
            assertThat(record.value().username()).isEqualTo("johndoe");
            assertThat(record.value().email()).isEqualTo("johndoe@example.com");
            assertThat(record.value().token()).isNotBlank();
        } finally {
            userRepository.deleteAll();
        }
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

        assertThat(applicationEvents.stream(EmailVerificationRequestedEvent.class))
                .singleElement()
                .extracting(EmailVerificationRequestedEvent::publicId)
                .isEqualTo(user.getPublicId());
    }

    private Consumer<String, EmailVerificationRequestedEvent> createTestConsumer() {
        var props = KafkaTestUtils.consumerProps(embeddedKafkaBroker, "registration-test", true);

        var valueDeserializer = new JacksonJsonDeserializer<>(EmailVerificationRequestedEvent.class)
                .ignoreTypeHeaders();

        return new DefaultKafkaConsumerFactory<>(props, new StringDeserializer(), valueDeserializer)
                .createConsumer();
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
