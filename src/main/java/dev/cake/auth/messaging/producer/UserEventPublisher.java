package dev.cake.auth.messaging.producer;

import dev.cake.auth.config.KafkaTopicProperties;
import dev.cake.auth.messaging.event.UserRegisteredEvent;
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

    private final KafkaTemplate<String, UserRegisteredEvent> kafkaTemplate;
    private final KafkaTopicProperties topics;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onUserRegistered(UserRegisteredEvent event) {
        kafkaTemplate.send(topics.userRegistered().name(), event.publicId().toString(), event)
                .whenComplete((result, ex) -> {
                    if (ex != null) {
                        log.error("Failed to publish UserRegisteredEvent for '{}'", event.publicId(), ex);
                    } else {
                        log.info("Published UserRegisteredEvent for '{}'", event.publicId());
                    }
                });
    }

}
