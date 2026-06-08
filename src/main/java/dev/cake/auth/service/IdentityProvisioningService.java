package dev.cake.auth.service;

import dev.cake.auth.entity.Identity;
import dev.cake.auth.entity.User;
import dev.cake.auth.repository.IdentityRepository;
import dev.cake.auth.repository.UserRepository;
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
                .filter(User::getEmailVerified)
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
}
