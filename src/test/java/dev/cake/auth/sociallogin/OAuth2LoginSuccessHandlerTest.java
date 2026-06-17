package dev.cake.auth.sociallogin;

import dev.cake.auth.common.TokenService;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class OAuth2LoginSuccessHandlerTest {

    @Mock
    TokenService tokenService;
    @Mock
    Authentication authentication;
    @Mock
    OAuth2User principal;

    @Test
    void writes_json_token_body_with_200_status() throws Exception {
        var handler = new OAuth2LoginSuccessHandler(tokenService, JsonMapper.builder().build());
        var request = new MockHttpServletRequest();
        var response = new MockHttpServletResponse();

        when(authentication.getPrincipal()).thenReturn(principal);
        when(principal.getName()).thenReturn("provider-subject-123");
        when(tokenService.generateToken("provider-subject-123")).thenReturn("signed.jwt.token");

        handler.onAuthenticationSuccess(request, response, authentication);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
        assertThat(response.getCharacterEncoding()).isEqualTo("UTF-8");
        assertThat(response.getContentAsString()).isEqualTo("{\"token\":\"signed.jwt.token\"}");
    }
}
