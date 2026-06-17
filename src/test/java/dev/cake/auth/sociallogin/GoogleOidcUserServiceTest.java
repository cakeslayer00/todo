package dev.cake.auth.sociallogin;

import dev.cake.auth.identity.AuthProvider;
import dev.cake.auth.identity.IdentityProvisioningService;
import dev.cake.auth.identity.User;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class GoogleOidcUserServiceTest {

    @Mock
    OidcUserService oidcUserService;
    @Mock
    IdentityProvisioningService provisioningService;
    @Mock
    OidcUserRequest userRequest;
    @Mock
    OidcUser oidcUser;

    @InjectMocks
    GoogleOidcUserService service;

    @Test
    void provisions_google_identity_and_wraps_user_when_email_verified() {
        var publicId = UUID.randomUUID();
        when(oidcUserService.loadUser(userRequest)).thenReturn(oidcUser);
        when(oidcUser.getEmailVerified()).thenReturn(true);
        when(oidcUser.getSubject()).thenReturn("google-sub");
        when(oidcUser.getEmail()).thenReturn("jane@example.com");
        when(provisioningService.provision(any()))
                .thenReturn(User.builder().publicId(publicId).build());

        var result = service.loadUser(userRequest);

        assertThat(result).isInstanceOf(CustomOidcUser.class);
        assertThat(result.getName()).isEqualTo(publicId.toString());

        var captor = ArgumentCaptor.forClass(FederatedUser.class);
        verify(provisioningService).provision(captor.capture());
        assertThat(captor.getValue())
                .isEqualTo(new FederatedUser(AuthProvider.GOOGLE, "google-sub", "jane@example.com", true));
    }

    @Test
    void throws_and_skips_provisioning_when_email_not_verified() {
        when(oidcUserService.loadUser(userRequest)).thenReturn(oidcUser);
        when(oidcUser.getEmailVerified()).thenReturn(false);

        assertThatThrownBy(() -> service.loadUser(userRequest))
                .isInstanceOf(OAuth2AuthenticationException.class);
        verify(provisioningService, never()).provision(any());
    }

    @Test
    void throws_and_skips_provisioning_when_email_verified_claim_is_absent() {
        when(oidcUserService.loadUser(userRequest)).thenReturn(oidcUser);
        when(oidcUser.getEmailVerified()).thenReturn(null);

        assertThatThrownBy(() -> service.loadUser(userRequest))
                .isInstanceOf(OAuth2AuthenticationException.class);
        verify(provisioningService, never()).provision(any());
    }

}
