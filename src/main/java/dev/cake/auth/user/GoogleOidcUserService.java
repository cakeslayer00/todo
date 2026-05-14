package dev.cake.auth.user;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Service
@RequiredArgsConstructor
public class GoogleOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private final UserRepository userRepository;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        var delegate = new OidcUserService();
        var oidcUser = delegate.loadUser(userRequest);

        var username = Objects.requireNonNull(oidcUser.getUserInfo().getClaims().get("given_name").toString());
        var email = Objects.requireNonNull(oidcUser.getEmail());
        var providerId = oidcUser.getSubject();

        if (userRepository.findUserByProviderId(providerId).isEmpty()) {
            userRepository.save(User.builder()
                    .username(username)
                    .email(email)
                    .providerId(providerId)
                    .authProvider(AuthProvider.GOOGLE)
                    .build());
        }

        return new CustomOidcUser(username, email);
    }
}
