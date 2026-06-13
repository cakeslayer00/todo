package dev.cake.auth.registration;

import dev.cake.auth.common.AbstractIntegrationTest;
import dev.cake.auth.identity.AuthProvider;
import dev.cake.auth.identity.IdentityRepository;
import dev.cake.auth.identity.User;
import dev.cake.auth.identity.UserRepository;
import dev.cake.auth.registration.event.UserRegisteredEvent;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.event.ApplicationEvents;
import org.springframework.test.context.event.RecordApplicationEvents;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@Transactional
@RecordApplicationEvents
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
public class RegistrationServiceIntegrationTest extends AbstractIntegrationTest {

    @Autowired
    RegistrationService registrationService;
    @Autowired
    ApplicationEvents applicationEvents;
    @Autowired
    UserRepository userRepository;
    @Autowired
    IdentityRepository identityRepository;

    @Test
    void when_user_registered_user_and_local_identity_are_persisted() {
        registrationService.register(
                new RegistrationRequest("john_doe", "john@example.com", "securePassword123"));

        Optional<User> optUser = userRepository.findByEmail("john@example.com");
        assertThat(optUser).isPresent();

        User user = optUser.get();
        assertThat(user.getUsername()).isEqualTo("john_doe");
        assertThat(user.getEmailVerified()).isFalse();
        assertThat(user.getPasswordHash()).isNotEqualTo("securePassword123");

        assertThat(identityRepository.findUserByProviderAndProviderSubject(
                AuthProvider.LOCAL, user.getPublicId().toString())).isPresent();
    }

    @Test
    void when_user_registered_application_event_publisher_emits_user_registered_event() {
        registrationService.register(
                new RegistrationRequest("jane_doe", "jane@example.com", "securePassword123"));

        User user = userRepository.findByEmail("jane@example.com").orElseThrow();
        assertThat(applicationEvents.stream(UserRegisteredEvent.class))
                .singleElement()
                .extracting(UserRegisteredEvent::publicId)
                .isEqualTo(user.getPublicId());
    }

}
