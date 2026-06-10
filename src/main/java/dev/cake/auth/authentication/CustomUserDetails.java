package dev.cake.auth.authentication;

import dev.cake.auth.identity.User;
import org.jspecify.annotations.NullMarked;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

@NullMarked
record CustomUserDetails(Long id,
                                String username,
                                String email,
                                Boolean emailVerified,
                                String passwordHash,
                                UUID publicId) implements UserDetails {

    CustomUserDetails(User user) {
        this(user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getEmailVerified(),
                user.getPasswordHash(),
                user.getPublicId()
        );
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    public String getPassword() {
        return passwordHash;
    }

    @Override
    public String getUsername() {
        return username();
    }

}
