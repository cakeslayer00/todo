package dev.cake.auth.registration;

import dev.cake.auth.common.AbstractIntegrationTest;
import dev.cake.auth.identity.UserRepository;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.test.web.servlet.assertj.MockMvcTester;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;

@AutoConfigureMockMvc
@Transactional
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
public class RegistrationControllerTest extends AbstractIntegrationTest {

    @Autowired
    MockMvcTester mockMvc;
    @Autowired
    UserRepository userRepository;

    @Test
    void valid_request_returns_201_and_persists_user() {
        assertThat(mockMvc.post().uri("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"username": "john_doe", "email": "john@example.com", "password": "securePassword123"}
                        """)
                .exchange())
                .hasStatus(HttpStatus.CREATED);

        assertThat(userRepository.findByEmail("john@example.com")).isPresent();
    }

    @Test
    void duplicate_email_returns_409() {
        var body = """
                {"username": "john_doe", "email": "john@example.com", "password": "securePassword123"}
                """;
        assertThat(mockMvc.post().uri("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body)
                .exchange())
                .hasStatus(HttpStatus.CREATED);

        assertThat(mockMvc.post().uri("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"username": "other_name", "email": "john@example.com", "password": "securePassword123"}
                        """)
                .exchange())
                .hasStatus(HttpStatus.CONFLICT)
                .bodyJson()
                .convertTo(ProblemDetail.class)
                .satisfies(detail -> assertThat(detail.getDetail()).contains("already taken"));
    }

    @Test
    void short_username_and_invalid_email_return_400_with_field_errors() {
        assertThat(mockMvc.post().uri("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"username": "ab", "email": "not-an-email", "password": "short"}
                        """)
                .exchange())
                .hasStatus(HttpStatus.BAD_REQUEST)
                .bodyJson()
                .convertTo(ProblemDetail.class)
                .satisfies(detail -> {
                    assertThat(detail.getDetail()).contains("username");
                    assertThat(detail.getDetail()).contains("email");
                    assertThat(detail.getDetail()).contains("password");
                });
    }
}
