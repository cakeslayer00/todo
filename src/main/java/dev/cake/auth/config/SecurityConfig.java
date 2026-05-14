package dev.cake.auth.config;

import dev.cake.auth.user.*;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.time.Instant;
import java.util.Objects;

@Slf4j
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   UserRepository userRepository,
                                                   JwtEncoder jwtEncoder) {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/**").permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .oauth2Login(oauth ->
                        oauth.authorizationEndpoint(authorization ->
                                authorization.baseUri("/api/v1/auth/login/oauth2/authorization")

                        ).redirectionEndpoint(redirection ->
                                redirection.baseUri("/api/v1/auth/login/oauth2/code/*")
                        ).userInfoEndpoint(userInfo ->
                                userInfo.userService(this.oauth2UserService(userRepository))
                                        .oidcUserService(this.oidcUserService(userRepository))
                        ).successHandler(this.oauth2LoginSuccessHandler(jwtEncoder))
                )
                .oauth2ResourceServer(oauth2 ->
                        oauth2.jwt(Customizer.withDefaults())
                )
                .exceptionHandling(ex ->
                        ex.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
                                .accessDeniedHandler(new BearerTokenAccessDeniedHandler())
                )
                .build();
    }

    private AuthenticationSuccessHandler oauth2LoginSuccessHandler(JwtEncoder encoder) {
        return (request, response, authentication) -> {
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.setStatus(HttpServletResponse.SC_OK);

            var now = Instant.now();
            var claims = JwtClaimsSet.builder()
                    .issuer("self")
                    .subject(authentication.getName())
                    .issuedAt(now)
                    .expiresAt(now.plusSeconds(3600))
                    .build();

            var token = encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
            var json = String.format("{\"token\": \"%s\"}", token);
            response.getWriter().write(json);
        };
    }

    private OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService(UserRepository userRepository) {
        return request -> {
            var oAuth2User = new DefaultOAuth2UserService().loadUser(request);
            var username = Objects.requireNonNull(oAuth2User.getAttributes().get("login").toString(),
                    "No username provided");
            var email = Objects.requireNonNull(oAuth2User.getAttributes().get("email").toString(), "No email provided");
            var providerId = oAuth2User.getAttributes().get("id").toString();

            var optUser = userRepository.findUserByProviderId(providerId);

            if (optUser.isEmpty()) {
                userRepository.save(User.builder()
                        .username(username)
                        .email(email)
                        .providerId(providerId)
                        .authProvider(AuthProvider.GITHUB)
                        .build());
            }
            return new CustomOAuth2User(username, email);
        };
    }

    private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService(UserRepository userRepository) {
        return request -> {
            var oidcUser = new OidcUserService().loadUser(request);
            var username = Objects.requireNonNull(oidcUser.getUserInfo().getClaims().get("given_name").toString(),
                    "No username provided");
            var email = Objects.requireNonNull(oidcUser.getEmail(), "No email provided");
            var providerId = oidcUser.getSubject();

            var optUser = userRepository.findUserByProviderId(providerId);

            if (optUser.isEmpty()) {
                userRepository.save(User.builder()
                        .username(username)
                        .email(email)
                        .providerId(providerId)
                        .authProvider(AuthProvider.GOOGLE)
                        .build());
            }
            return new CustomOidcUser(username, email);
        };
    }

}
