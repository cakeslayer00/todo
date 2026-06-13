package dev.cake.auth.common;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.kafka.test.context.EmbeddedKafka;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@ActiveProfiles("test")
@Import(TestConfiguration.class)
@EmbeddedKafka(topics = "auth.email-verification-requested", partitions = 1)
public abstract class AbstractIntegrationTest {
}
