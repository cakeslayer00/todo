package dev.cake.auth.identity;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface IdentityRepository extends JpaRepository<Identity, Long> {

    @Query("select i.user from Identity i where i.provider = ?1 and i.providerSubject = ?2")
    Optional<User> findUserByProviderAndProviderSubject(AuthProvider provider, String subject);

    @Query("select i.user from Identity i where i.user.id = ?1")
    Optional<User> findUserByUserId(Long id);
}

