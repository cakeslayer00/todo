package dev.cake.auth.emailverification;

import dev.cake.auth.common.AbstractIntegrationTest;
import dev.cake.auth.emailverification.event.EmailVerificationRequestedEvent;
import dev.cake.auth.identity.User;
import dev.cake.auth.identity.UserRepository;
import dev.cake.auth.messaging.configuration.KafkaTopicProperties;
import dev.cake.auth.registration.event.UserRegisteredEvent;
import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.common.serialization.StringDeserializer;
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

import static org.assertj.core.api.Assertions.assertThat;

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
    void when_valid_token_received_email_verified() {
        var user = userRepository.save(User.builder()
                .username("johndoe")
                .email("johndoe@example.com")
                .emailVerified(false)
                .build());

        var token = issueVerificationToken(user);
        emailVerificationService.verify(token);

        var hash = emailVerificationTokenService.hash(token);
        Optional<EmailVerification> optEV = emailVerificationRepository.findByTokenHash(hash);

        assertThat(optEV).isPresent();
        assertThat(optEV.get().getConsumedAt()).isBefore(Instant.now());
        assertThat(optEV.get().getUser().getEmailVerified()).isTrue();
    }

    @Test
    void when_user_registered_event_published_email_verification_event_emitted() {
        var user = userRepository.saveAndFlush(User.builder()
                .username("johndoe")
                .email("johndoe@example.com")
                .emailVerified(false)
                .build());

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

            var user = userRepository.saveAndFlush(User.builder()
                    .username("johndoe")
                    .email("johndoe@example.com")
                    .emailVerified(false)
                    .build());

            txTemplate.executeWithoutResult(_ -> {
                userRepository.save(user);
                applicationEventPublisher.publishEvent(new UserRegisteredEvent(user.getPublicId()));
            });

            ConsumerRecord<String, EmailVerificationRequestedEvent> record =
                    KafkaTestUtils.getSingleRecord(consumer, kafkaTopicProperties.emailVerificationRequested().name(), Duration.ofSeconds(10));

            assertThat(record.key()).isEqualTo(user.getPublicId().toString());
            assertThat(record.value().publicId()).isEqualTo(user.getPublicId());
            assertThat(record.value().username()).isEqualTo("johndoe");
            assertThat(record.value().email()).isEqualTo("johndoe@example.com");
            assertThat(record.value().token()).isNotBlank();

            userRepository.deleteAll();
        }
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
        emailVerificationRepository.save(EmailVerification.builder()
                .user(user)
                .tokenHash(generatedToken.tokenHash())
                .expiresAt(Instant.now().plus(emailVerificationTokenProperties.expiry()))
                .build());

        return generatedToken.rawToken();
    }

}
