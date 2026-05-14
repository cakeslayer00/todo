package dev.cake.auth.auth;

import dev.cake.auth.exception.DuplicateResourceException;
import dev.cake.auth.user.AuthProvider;
import dev.cake.auth.user.User;
import dev.cake.auth.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;

    public AuthResponse login(AuthRequest request) {
        var authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password())
        );

        var token = tokenService.generateToken(authentication.getName());
        log.info("User authenticated with username: '{}'", authentication.getName());
        return new AuthResponse(token, authentication.getName());
    }

    public void register(RegistrationRequest request) {
        if (userRepository.findByUsername(request.username()).isPresent()) {
            throw new DuplicateResourceException("Username", request.username());
        }
        if (userRepository.findByEmail(request.email()).isPresent()) {
            throw new DuplicateResourceException("Email", request.email());
        }

        var user = User.builder()
                .username(request.username())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .authProvider(AuthProvider.LOCAL)
                .build();

        log.info("User registered with username: '{}'", user.getUsername());
        userRepository.save(user);
    }

}
