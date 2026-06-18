package dev.cake.auth.messaging.configuration;

import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.common.config.TopicConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;

@Configuration
public class KafkaTopicConfig {

    @Bean
    public NewTopic emailVerificationRequestedTopic(KafkaTopicProperties topics) {
        var spec = topics.emailVerificationRequested();
        return TopicBuilder.name(spec.name())
                .partitions(spec.partitions())
                .replicas(spec.replicas())
                .config(TopicConfig.RETENTION_MS_CONFIG, String.valueOf(spec.retention().toMillis()))
                .build();
    }

}