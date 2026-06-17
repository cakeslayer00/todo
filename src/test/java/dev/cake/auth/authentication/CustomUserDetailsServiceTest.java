package dev.cake.auth.authentication;

import dev.cake.auth.identity.User;
import dev.cake.auth.identity.UserRepository;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class CustomUserDetailsServiceTest {

    @Mock
    UserRepository userRepository;
    @InjectMocks
    CustomUserDetailsService customUserDetailsService;

    @Test
    void loads_user_details_when_email_exists() {
        var user = User.builder()
                .id(1L)
                .publicId(UUID.randomUUID())
                .username("johndoe")
                .email("johndoe@example.com")
                .emailVerified(true)
                .passwordHash("hash")
                .build();
        when(userRepository.findByEmail("johndoe@example.com")).thenReturn(Optional.of(user));

        var details = customUserDetailsService.loadUserByUsername("johndoe@example.com");

        assertThat(details).isInstanceOf(CustomUserDetails.class);
        assertThat(details.getUsername()).isEqualTo("johndoe");
        assertThat(details.getPassword()).isEqualTo("hash");
        assertThat(((CustomUserDetails) details).publicId()).isEqualTo(user.getPublicId());
    }

    @Test
    void throws_when_email_not_found() {
        when(userRepository.findByEmail("missing@example.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> customUserDetailsService.loadUserByUsername("missing@example.com"))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining("missing@example.com");
    }
}
