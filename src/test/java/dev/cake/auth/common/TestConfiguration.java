package dev.cake.auth.common;

import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.testcontainers.postgresql.PostgreSQLContainer;

@org.springframework.boot.test.context.TestConfiguration(proxyBeanMethods = false)
public class TestConfiguration {

    @Bean
    @ServiceConnection
    PostgreSQLContainer postgreSQLContainer() {
        return new PostgreSQLContainer("postgres:17-alpine");
    }

}
