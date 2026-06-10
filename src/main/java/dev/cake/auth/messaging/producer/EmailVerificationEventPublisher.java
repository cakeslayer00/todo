package dev.cake.auth.messaging.producer;

import dev.cake.auth.messaging.configuration.KafkaTopicProperties;
import dev.cake.auth.emailverification.event.EmailVerificationRequestedEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Slf4j
@Component
@RequiredArgsConstructor
class EmailVerificationEventPublisher {

    private final KafkaTemplate<String, EmailVerificationRequestedEvent> kafkaTemplate;
    private final KafkaTopicProperties topics;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    void onEmailVerificationRequested(EmailVerificationRequestedEvent event) {
        kafkaTemplate.send(topics.emailVerificationRequested().name(), event.publicId().toString(), event)
                .whenComplete((_, ex) -> {
                    if (ex != null) {
                        log.error("Failed to publish EmailVerificationRequestedEvent for '{}'", event.publicId(), ex);
                    } else {
                        log.info("Published EmailVerificationRequestedEvent for '{}'", event.publicId());
                    }
                });
    }

}
