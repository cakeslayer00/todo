package dev.cake.auth.emailverification;

import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@Service
class EmailVerificationTokenService {

    private final StringKeyGenerator tokenGenerator =
            new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 32);

    GeneratedToken generate() {
        String rawToken = tokenGenerator.generateKey();
        return new GeneratedToken(rawToken, hash(rawToken));
    }

    /**
     * Hashes a token for storage / lookup. The token is already high-entropy,
     * so a plain SHA-256 is correct here (no bcrypt/argon2 — those are for
     * low-entropy passwords, and they're non-deterministic so you couldn't
     * look up by hash anyway).
     */
    String hash(String rawToken) {
        byte[] digest = sha256().digest(rawToken.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    record GeneratedToken(String rawToken, String tokenHash) {}

}