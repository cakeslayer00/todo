package dev.cake.auth.user;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Objects;

@Service
@RequiredArgsConstructor
public class GitHubOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        var delegate = new DefaultOAuth2UserService();
        var oAuth2User = delegate.loadUser(userRequest);

        var username = Objects.requireNonNull(oAuth2User.getAttributes().get("login").toString());
        var email = Objects.requireNonNull(oAuth2User.getAttributes().get("email").toString());
        var providerId = oAuth2User.getAttributes().get("id").toString();

        if (userRepository.findUserByProviderId(providerId).isEmpty()) {
            userRepository.save(User.builder()
                    .username(username)
                    .email(email)
                    .providerId(providerId)
                    .authProvider(AuthProvider.GITHUB)
                    .build());
        }

        return new CustomOAuth2User(username, email);
    }
}
