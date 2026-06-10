package dev.cake.auth.messaging.configuration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties(prefix = "app.kafka.topics")
public record KafkaTopicProperties(TopicSpec emailVerificationRequested) {

    public record TopicSpec(String name,
                            @DefaultValue("3") int partitions,
                            @DefaultValue("1") int replicas) {
    }

}
