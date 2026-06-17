package dev.cake.auth.registration;

import dev.cake.auth.common.exception.DuplicateResourceException;
import dev.cake.auth.identity.*;
import dev.cake.auth.registration.event.UserRegisteredEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
class RegistrationService {

    private final UserRepository userRepository;
    private final IdentityRepository identityRepository;

    private final PasswordEncoder passwordEncoder;

    private final ApplicationEventPublisher applicationEventPublisher;

    @Transactional
    void register(RegistrationRequest request) {
        if (userRepository.findByEmail(request.email()).isPresent()) {
            throw new DuplicateResourceException("Email", request.email());
        }

        var user = User.builder()
                .username(request.username())
                .email(request.email())
                .emailVerified(false)
                .passwordHash(passwordEncoder.encode(request.password()))
                .build();

        userRepository.saveAndFlush(user);
        log.info("User registered with username: '{}'", user.getUsername());

        var identity = Identity.builder()
                .user(user)
                .provider(AuthProvider.LOCAL)
                .providerSubject(String.valueOf(user.getPublicId()))
                .build();

        identityRepository.save(identity);
        log.info("Local provider identity added to user: '{}'", identity.getProviderSubject());

        applicationEventPublisher.publishEvent(new UserRegisteredEvent(user.getPublicId()));
        log.info("UserRegisteredEvent emitted for user '{}'", user.getPublicId());
    }

}
