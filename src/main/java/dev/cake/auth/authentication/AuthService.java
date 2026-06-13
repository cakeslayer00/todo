package dev.cake.auth.authentication;

import dev.cake.auth.common.TokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Slf4j
@Service
@RequiredArgsConstructor
class AuthService {

    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;

    AuthResponse login(AuthRequest request) {
        var authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.email(), request.password())
        );

        var token = tokenService.generateToken(String.valueOf(
                ((CustomUserDetails) Objects.requireNonNull(authentication.getPrincipal())).publicId()
        ));

        log.info("User '{}' authenticated", authentication.getName());
        return new AuthResponse(token, authentication.getName());
    }

}
