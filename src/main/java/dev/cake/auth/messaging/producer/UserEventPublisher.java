package dev.cake.auth.messaging.producer;

import dev.cake.auth.config.KafkaTopicProperties;
import dev.cake.auth.messaging.event.EmailVerificationRequestedEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Slf4j
@Component
@RequiredArgsConstructor
public class UserEventPublisher {

    private final KafkaTemplate<String, Object> kafkaTemplate;
    private final KafkaTopicProperties topics;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onEmailVerificationRequested(EmailVerificationRequestedEvent event) {
        kafkaTemplate.send(topics.emailVerificationRequested().name(), event.publicId().toString(), event)
                .whenComplete((result, ex) -> {
                    if (ex != null) {
                        log.error("Failed to publish EmailVerificationRequestedEvent for '{}'", event.publicId(), ex);
                    } else {
                        log.info("Published EmailVerificationRequestedEvent for '{}'", event.publicId());
                    }
                });
    }

}
