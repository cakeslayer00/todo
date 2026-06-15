package dev.cake.auth.sociallogin;

import dev.cake.auth.identity.AuthProvider;
import dev.cake.auth.identity.IdentityProvisioningService;
import dev.cake.auth.identity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

@ExtendWith(MockitoExtension.class)
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class GitHubOAuth2UserServiceTest {

    @Mock
    IdentityProvisioningService provisioningService;
    @Mock
    DefaultOAuth2UserService defaultOAuth2UserService;

    MockRestServiceServer server;
    GitHubOAuth2UserService service;

    @Mock
    OAuth2UserRequest userRequest;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        RestClient restClient = builder.build();

        service = new GitHubOAuth2UserService(provisioningService, restClient, defaultOAuth2UserService);

        OAuth2AccessToken token = mock(OAuth2AccessToken.class);
        when(userRequest.getAccessToken()).thenReturn(token);
        when(token.getTokenValue()).thenReturn("gh-token");
    }

    @Test
    void provisions_github_identity_with_primary_verified_email_and_wraps_user() {
        OAuth2User ghUser = mock(OAuth2User.class);
        when(ghUser.getAttributes()).thenReturn(Map.of("id", 12345));
        when(defaultOAuth2UserService.loadUser(userRequest)).thenReturn(ghUser);

        server.expect(requestTo("https://api.github.com/user/emails"))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer gh-token"))
                .andRespond(withSuccess("""
                        [
                          {"email":"secondary@example.com","primary":false,"verified":true},
                          {"email":"primary@example.com","primary":true,"verified":true}
                        ]
                        """, MediaType.APPLICATION_JSON));

        var publicId = UUID.randomUUID();
        when(provisioningService.provision(any()))
                .thenReturn(User.builder().publicId(publicId).build());

        var result = service.loadUser(userRequest);

        server.verify();
        assertThat(result).isInstanceOf(CustomOAuth2User.class);
        assertThat(result.getName()).isEqualTo(publicId.toString());

        var captor = ArgumentCaptor.forClass(FederatedUser.class);
        verify(provisioningService).provision(captor.capture());
        assertThat(captor.getValue())
                .isEqualTo(new FederatedUser(AuthProvider.GITHUB, "12345", "primary@example.com", true));
    }

    @Test
    void throws_and_skips_provisioning_when_no_primary_verified_email() {
        OAuth2User ghUser = mock(OAuth2User.class);
        when(defaultOAuth2UserService.loadUser(userRequest)).thenReturn(ghUser);

        server.expect(requestTo("https://api.github.com/user/emails"))
                .andRespond(withSuccess("""
                        [
                          {"email":"primary@example.com","primary":true,"verified":false},
                          {"email":"verified@example.com","primary":false,"verified":true}
                        ]
                        """, MediaType.APPLICATION_JSON));

        assertThatThrownBy(() -> service.loadUser(userRequest))
                .isInstanceOf(OAuth2AuthenticationException.class);
        verify(provisioningService, never()).provision(any());
    }

    @Test
    void throws_and_skips_provisioning_when_github_returns_no_emails() {
        OAuth2User ghUser = mock(OAuth2User.class);
        when(defaultOAuth2UserService.loadUser(userRequest)).thenReturn(ghUser);

        server.expect(requestTo("https://api.github.com/user/emails"))
                .andRespond(withSuccess("[]", MediaType.APPLICATION_JSON));

        assertThatThrownBy(() -> service.loadUser(userRequest))
                .isInstanceOf(OAuth2AuthenticationException.class);
        verify(provisioningService, never()).provision(any());
    }

}
