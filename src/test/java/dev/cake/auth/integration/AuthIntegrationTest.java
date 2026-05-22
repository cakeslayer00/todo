package dev.cake.auth.integration;

import dev.cake.auth.dto.AuthRequest;
import dev.cake.auth.dto.AuthResponse;
import dev.cake.auth.dto.RegistrationRequest;
import dev.cake.auth.entity.AuthProvider;
import dev.cake.auth.entity.User;
import dev.cake.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.assertj.MockMvcTester;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;

class AuthIntegrationTest extends BaseIntegrationTest {

    @Autowired
    MockMvcTester mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
        userRepository.save(User.builder()
                .username("cakeslayer")
                .email("cakeslayer@gmail.com")
                .password(passwordEncoder.encode("password67"))
                .build());

        userRepository.save(User.builder()
                .username("oauth2Cake")
                .email("oauth2cakeslayer@gmail.com")
                .providerId("someProviderId")
                .authProvider(AuthProvider.GITHUB)
                .build());
    }

    @Test
    void register_withValidRequestBody_shouldReturn201() {
        var requestBody = new RegistrationRequest(
                "vladislav",
                "genericemail@gmail.com",
                "password");

        mockMvc.post()
                .uri("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestBody))
                .assertThat()
                .hasStatus(HttpStatus.CREATED);

        assertThat(userRepository.findByEmail(requestBody.email())).isPresent();
    }

    @Test
    void register_withDuplicateUser_shouldReturn409() {
        var requestBody = new RegistrationRequest(
                "cakeslayer",
                "cakeslayer@gmail.com",
                "password67");

        mockMvc.post()
                .uri("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestBody))
                .assertThat()
                .hasStatus(HttpStatus.CONFLICT);
    }


    @Test
    void register_withInvalidUserCredentials_shouldReturn400() {
        var requestBody = new RegistrationRequest(
                "ck",
                "c.com",
                "123");

        mockMvc.post()
                .uri("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestBody))
                .assertThat()
                .hasStatus(HttpStatus.BAD_REQUEST);
    }

    @Test
    void login_withValidUserCredentials_shouldReturnTokenAndUsername() {
        var requestBody = new AuthRequest("cakeslayer", "password67");

        mockMvc.post()
                .uri("/api/v1/auth")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestBody))
                .assertThat()
                .hasStatusOk()
                .bodyJson()
                .convertTo(AuthResponse.class)
                .satisfies(auth -> {
                    assertThat(auth.username()).isEqualTo("cakeslayer");
                    assertThat(auth.accessToken()).isNotEmpty();
                });
    }

    @Test
    void login_withWrongUserCredentials_shouldReturn401() {
        var requestBody = new AuthRequest("cakeslayer", "password66");

        mockMvc.post()
                .uri("/api/v1/auth")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestBody))
                .assertThat()
                .hasStatus(HttpStatus.BAD_REQUEST);
    }

    @Test
    void login_withInvalidUserCredentials_shouldReturn401() {
        var requestBody = new AuthRequest("ca", "asdf");

        mockMvc.post()
                .uri("/api/v1/auth")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestBody))
                .assertThat()
                .hasStatus(HttpStatus.BAD_REQUEST);
    }

}
