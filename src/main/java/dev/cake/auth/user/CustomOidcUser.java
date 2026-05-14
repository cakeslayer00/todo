package dev.cake.auth.user;


import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Getter
public class CustomOidcUser implements OidcUser {

    private final String name;
    private final Map<String, Object> attributes;

    public CustomOidcUser(String name, String email) {
        this.name = name;
        this.attributes = new HashMap<>();
        attributes.put("email", email);
    }

    @Override
    public Map<String, Object> getClaims() {
        return Map.of();
    }

    @Override
    public OidcUserInfo getUserInfo() {
        return null;
    }

    @Override
    public OidcIdToken getIdToken() {
        return null;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }
}
