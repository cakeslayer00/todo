package dev.cake.auth.service;

import dev.cake.auth.entity.AuthProvider;
import dev.cake.auth.security.CustomOidcUser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class GoogleOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private final IdentityProvisioningService provisioningService;
    private final OidcUserService oidcUserService;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        var oidcUser = oidcUserService.loadUser(userRequest);

        if (!Boolean.TRUE.equals(oidcUser.getEmailVerified())) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("email_unavailable"),
                    "Google account has no verified email");
        }

        var user = provisioningService.provision(new FederatedUser(
                AuthProvider.GOOGLE,
                oidcUser.getSubject(),
                oidcUser.getEmail(),
                true));

        return new CustomOidcUser(user.getPublicId(), oidcUser);
    }

}
