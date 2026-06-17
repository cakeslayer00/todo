package dev.cake.auth.identity;

import dev.cake.auth.sociallogin.FederatedUser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class IdentityProvisioningService {

    private final UserRepository userRepository;
    private final IdentityRepository identityRepository;

    @Transactional
    public User provision(FederatedUser federated) {
        var linked = identityRepository
                .findUserByProviderAndProviderSubject(federated.provider(), federated.subject());
        if (linked.isPresent()) {
            return linked.get();
        }

        var user = userRepository.findByEmail(federated.email())
                .map(existing -> claim(existing, federated))
                .orElseGet(() -> userRepository.save(User.builder()
                        .email(federated.email())
                        .emailVerified(federated.emailVerified())
                        .build()));

        identityRepository.save(Identity.builder()
                .user(user)
                .provider(federated.provider())
                .providerSubject(federated.subject())
                .build());

        log.info("Linked {} identity to user '{}'", federated.provider(), user.getPublicId());
        return user;
    }

    /**
     * Resolves which user a federated login should attach to when an account with the same email
     * already exists.
     * <p>
     * A verified account has already proven ownership of the email, so it is safe to link to.
     * An <em>unverified</em> account is untrusted: it may have been pre-registered by an attacker
     * to later ride along on the victim's federated login (pre-account-hijacking). A
     * provider-verified login is stronger proof of ownership, so it claims the account — marking
     * the email verified and discarding the untrusted local password so the pre-registered
     * credential can no longer be used. If the federated email is itself unverified, neither side
     * has proven ownership, so the identity is linked without elevating trust.
     */
    private User claim(User user, FederatedUser federated) {
        if (user.isEmailVerified() || !federated.emailVerified()) {
            return user;
        }

        user.setEmailVerified(true);
        user.setPasswordHash(null);
        log.info("Claimed unverified account '{}' via verified {} login",
                user.getPublicId(), federated.provider());
        return userRepository.save(user);
    }
}
