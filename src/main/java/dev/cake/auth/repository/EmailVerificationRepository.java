package dev.cake.auth.repository;

import dev.cake.auth.entity.EmailVerification;
import dev.cake.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;

public interface EmailVerificationRepository extends JpaRepository<EmailVerification, Long> {

    Optional<EmailVerification> findByTokenHash(String tokenHash);

    /**
     * Marks every still-live token for a user as consumed, so a freshly issued
     * one is the only link that works. Bulk update — runs as a single statement.
     */
    @Modifying
    @Query("update EmailVerification ev set ev.consumedAt = :now " +
            "where ev.user = :user and ev.consumedAt is null")
    void consumeAllActiveForUser(@Param("user") User user, @Param("now") Instant now);

}
