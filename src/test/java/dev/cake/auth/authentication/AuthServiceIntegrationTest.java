package dev.cake.auth.authentication;

import dev.cake.auth.authentication.dto.AuthRequest;
import dev.cake.auth.common.AbstractIntegrationTest;
import dev.cake.auth.identity.User;
import dev.cake.auth.identity.UserRepository;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;

@Transactional
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
public class AuthServiceIntegrationTest extends AbstractIntegrationTest {

    @Autowired
    AuthService authService;
    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    UserRepository userRepository;

    @Test
    void return_auth_response_after_authentication_with_valid_credentials() {
        userRepository.save(User.builder()
                .username("johndoe")
                .email("johndoe@example.com")
                .emailVerified(false)
                .passwordHash(passwordEncoder.encode("password"))
                .build());

        var request = new AuthRequest("johndoe@example.com", "password");
        var response = authService.login(request);

        assertThat(response.accessToken()).isNotBlank();
        assertThat(response.username()).isEqualTo("johndoe");
    }

}
