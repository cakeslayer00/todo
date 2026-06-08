package dev.cake.auth.service;

import dev.cake.auth.dto.AuthRequest;
import dev.cake.auth.dto.AuthResponse;
import dev.cake.auth.dto.RegistrationRequest;
import dev.cake.auth.entity.AuthProvider;
import dev.cake.auth.entity.Identity;
import dev.cake.auth.entity.User;
import dev.cake.auth.exception.DuplicateResourceException;
import dev.cake.auth.messaging.event.UserRegisteredEvent;
import dev.cake.auth.repository.IdentityRepository;
import dev.cake.auth.repository.UserRepository;
import dev.cake.auth.security.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final IdentityRepository identityRepository;

    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManager authenticationManager;

    private final TokenService tokenService;

    private final ApplicationEventPublisher eventPublisher;

    public AuthResponse login(AuthRequest request) {
        var authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.email(), request.password())
        );

        var token = tokenService.generateToken(String.valueOf(
                ((CustomUserDetails) Objects.requireNonNull(authentication.getPrincipal())).publicId()
        ));
        log.info("User authenticated with username: '{}'", authentication.getName());
        return new AuthResponse(token, authentication.getName());
    }

    @Transactional
    public void register(RegistrationRequest request) {
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

        eventPublisher.publishEvent(new UserRegisteredEvent(user.getPublicId(), user.getEmail()));
        log.info("Published UserRegisteredEvent for kafka producer to pick up");
    }

}
