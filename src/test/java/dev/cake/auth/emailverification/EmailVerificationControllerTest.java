package dev.cake.auth.emailverification;

import dev.cake.auth.common.AbstractIntegrationTest;
import dev.cake.auth.emailverification.event.EmailVerificationRequestedEvent;
import dev.cake.auth.identity.User;
import dev.cake.auth.identity.UserRepository;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.test.context.event.ApplicationEvents;
import org.springframework.test.context.event.RecordApplicationEvents;
import org.springframework.test.web.servlet.assertj.MockMvcTester;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;

@AutoConfigureMockMvc
@Transactional
@RecordApplicationEvents
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
public class EmailVerificationControllerTest extends AbstractIntegrationTest {

    @Autowired
    MockMvcTester mockMvc;
    @Autowired
    UserRepository userRepository;
    @Autowired
    EmailVerificationRepository emailVerificationRepository;
    @Autowired
    EmailVerificationTokenService tokenService;
    @Autowired
    EmailVerificationTokenProperties tokenProperties;
    @Autowired
    ApplicationEvents applicationEvents;

    @Test
    void valid_token_returns_200_and_marks_email_verified() {
        var user = persistUser(false);
        var generated = tokenService.generate();
        emailVerificationRepository.save(EmailVerification.builder()
                .user(user)
                .tokenHash(generated.tokenHash())
                .expiresAt(Instant.now().plus(tokenProperties.expiry()))
                .build());

        assertThat(mockMvc.post().uri("/api/v1/auth/verify")
                .param("token", generated.rawToken())
                .exchange())
                .hasStatusOk();

        assertThat(userRepository.findByPublicId(user.getPublicId()))
                .get()
                .extracting(User::getEmailVerified)
                .isEqualTo(true);
    }

    @Test
    void invalid_token_returns_400_problem_detail() {
        assertThat(mockMvc.post().uri("/api/v1/auth/verify")
                .param("token", "not real token")
                .exchange())
                .hasStatus(HttpStatus.BAD_REQUEST)
                .bodyJson()
                .convertTo(ProblemDetail.class)
                .satisfies(detail -> assertThat(detail.getDetail()).isEqualTo("Invalid verification token"));
    }

    @Test
    void resend_without_authentication_returns_401() {
        assertThat(mockMvc.post().uri("/api/v1/auth/verify/resend")
                .exchange())
                .hasStatus(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void resend_authenticated_returns_202_and_publishes_event() {
        var user = persistUser(false);
        assertThat(mockMvc.post().uri("/api/v1/auth/verify/resend")
                .with(jwt().jwt(j -> j.subject(user.getPublicId().toString()))))
                .hasStatus(HttpStatus.ACCEPTED);

        assertThat(applicationEvents.stream(EmailVerificationRequestedEvent.class))
                .singleElement()
                .extracting(EmailVerificationRequestedEvent::publicId)
                .isEqualTo(user.getPublicId());
    }

    @Test
    void resend_for_already_verified_user_returns_400() {
        var user = persistUser(true);

        assertThat(mockMvc.post().uri("/api/v1/auth/verify/resend")
                .with(jwt().jwt(j -> j.subject(user.getPublicId().toString()))))
                .hasStatus(HttpStatus.BAD_REQUEST)
                .bodyJson()
                .convertTo(ProblemDetail.class)
                .satisfies(detail ->
                        assertThat(detail.getDetail()).isEqualTo("Email already verified"));
    }

    private User persistUser(boolean emailVerified) {
        return userRepository.saveAndFlush(User.builder()
                .username("johndoe-" + UUID.randomUUID())
                .email(UUID.randomUUID() + "@example.com")
                .emailVerified(emailVerified)
                .build());
    }
}
