package dev.cake.auth.common.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@ConfigurationProperties("app.jwt")
public record RSAKeyProperties(RSAPublicKey publicKey,
                               RSAPrivateKey privateKey) {
}
