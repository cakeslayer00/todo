package dev.cake.auth.sociallogin;

import dev.cake.auth.identity.AuthProvider;
import dev.cake.auth.identity.IdentityProvisioningService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class GitHubOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final IdentityProvisioningService provisioningService;
    private final RestClient restClient;
    private final DefaultOAuth2UserService defaultOAuth2UserService;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        var oAuth2User = defaultOAuth2UserService.loadUser(userRequest);
        var primaryEmail = fetchPrimaryEmail(userRequest.getAccessToken().getTokenValue());

        if (primaryEmail == null) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("email_unavailable"),
                    "GitHub account has no verified primary email");
        }

        var user = provisioningService.provision(new FederatedUser(
                AuthProvider.GITHUB,
                oAuth2User.getAttributes().get("id").toString(),
                primaryEmail.email(),
                primaryEmail.verified()));

        return new CustomOAuth2User(user.getPublicId(), oAuth2User);
    }

    private record GitHubEmail(String email, boolean primary, boolean verified) {}

    private GitHubEmail fetchPrimaryEmail(String accessToken) {
        var emails = restClient.get()
                .uri("https://api.github.com/user/emails")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .body(new ParameterizedTypeReference<List<GitHubEmail>>() {});

        return emails == null ? null : emails.stream()
                .filter(GitHubEmail::primary)
                .filter(GitHubEmail::verified)
                .findFirst()
                .orElse(null);
    }

}
