package dev.cake.auth.outbox;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.cake.auth.emailverification.event.EmailVerificationRequested;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * Runs as a plain {@code @EventListener}, so the insert happens inside the same
 * transaction that issued the verification token — the business change and the
 * event are persisted atomically. Debezium tails the WAL
 * and ships the row to Kafka; nothing here talks to a broker.
 */
@Slf4j
@Component
@RequiredArgsConstructor
class EmailVerificationOutboxWriter {

    private static final String AGGREGATE_TYPE = "email_verification";
    private static final String EVENT_TYPE = "EmailVerificationRequested";

    private final OutboxEventRepository outboxEventRepository;
    private final ObjectMapper objectMapper;

    @EventListener
    void onEmailVerificationRequested(EmailVerificationRequested event) {
        outboxEventRepository.save(OutboxEvent.builder()
                .id(UUID.randomUUID())
                .aggregateType(AGGREGATE_TYPE)
                .aggregateId(event.publicId().toString())
                .type(EVENT_TYPE)
                .payload(serialize(event))
                .build());

        log.info("Wrote EmailVerificationRequested to outbox for '{}'", event.publicId());
    }

    private String serialize(EmailVerificationRequested event) {
        try {
            return objectMapper.writeValueAsString(event);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(
                    "Failed to serialize EmailVerificationRequested for outbox", e);
        }
    }

}
