package dev.cake.auth.authentication;

import dev.cake.auth.common.AbstractIntegrationTest;
import dev.cake.auth.identity.User;
import dev.cake.auth.identity.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.assertj.MockMvcTester;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;

@AutoConfigureMockMvc
@Transactional
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
public class AuthControllerTest extends AbstractIntegrationTest {

    @Autowired
    MockMvcTester mockMvc;
    @Autowired
    UserRepository userRepository;
    @Autowired
    PasswordEncoder passwordEncoder;

    @BeforeEach
    void seedUser() {
        userRepository.save(User.builder()
                .username("johndoe")
                .email("johndoe@example.com")
                .emailVerified(false)
                .passwordHash(passwordEncoder.encode("password"))
                .build());
    }

    @Test
    void valid_credentials_return_200_with_token_and_username() {
        assertThat(mockMvc.post().uri("/api/v1/auth")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"email": "johndoe@example.com", "password": "password"}
                        """)
                .exchange())
                .hasStatusOk()
                .hasContentTypeCompatibleWith(MediaType.APPLICATION_JSON)
                .bodyJson()
                .convertTo(AuthResponse.class)
                .satisfies(authResponse -> {
                    assertThat(authResponse.accessToken()).isNotEmpty();
                    assertThat(authResponse.username()).isEqualTo("johndoe");
                })
        ;
    }

    @Test
    void invalid_credentials_return_401_problem_detail() {
        assertThat(mockMvc.post().uri("/api/v1/auth")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"email": "johndoe@example.com", "password": "wrong-password"}
                        """)
                .exchange())
                .hasStatus(HttpStatus.UNAUTHORIZED)
                .bodyJson()
                .convertTo(ProblemDetail.class)
                .satisfies(detail ->
                        assertThat(detail.getDetail())
                                .isEqualTo("User with provided credentials doesn't exist"));
    }

    @Test
    void malformed_email_and_short_password_return_400_with_field_errors() {
        assertThat(mockMvc.post().uri("/api/v1/auth")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"email": "not-an-email", "password": "short"}
                        """)
                .exchange())
                .hasStatus(HttpStatus.BAD_REQUEST)
                .bodyJson()
                .convertTo(ProblemDetail.class)
                .satisfies(detail -> {
                    assertThat(detail.getDetail()).contains("email");
                    assertThat(detail.getDetail()).contains("password");
                });
    }

    @Test
    void blank_body_returns_400() {
        assertThat(mockMvc.post().uri("/api/v1/auth")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"email": "", "password": ""}
                        """)
                .exchange())
                .hasStatus(HttpStatus.BAD_REQUEST);
    }
}
