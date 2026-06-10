package dev.cake.auth.common.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "openapi")
public record OpenApiProperties(String serverUrl,
                                String contactName,
                                String contactEmail,
                                String version) {
}
