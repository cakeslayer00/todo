package dev.cake.auth.service;

import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@Service
public class VerificationTokenService {

    private final StringKeyGenerator tokenGenerator =
            new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 32);

    public GeneratedToken generate() {
        String rawToken = tokenGenerator.generateKey();
        return new GeneratedToken(rawToken, hash(rawToken));
    }

    /**
     * Hashes a token for storage / lookup. The token is already high-entropy,
     * so a plain SHA-256 is correct here (no bcrypt/argon2 — those are for
     * low-entropy passwords, and they're non-deterministic so you couldn't
     * look up by hash anyway).
     */
    public String hash(String rawToken) {
        byte[] digest = sha256().digest(rawToken.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    public record GeneratedToken(String rawToken, String tokenHash) {}

}