package dev.cake.auth.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.media.StringSchema;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import lombok.RequiredArgsConstructor;
import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.Map;

@Configuration
@RequiredArgsConstructor
public class OpenApiConfig {


    private final OpenApiProperties properties;

    @Bean

    public OpenAPI openAPI() {
        var server = new Server()
                .url(properties.serverUrl())
                .description("Local Dev");

        var contact = new Contact()
                .name(properties.contactName())
                .email(properties.contactEmail());

        var information = new Info()
                .title("Authentication Service API")
                .description("REST API for user authentication, registration, and OAuth2 login")
                .version(properties.version())
                .contact(contact);

        var bearerScheme = new SecurityScheme()
                .type(SecurityScheme.Type.HTTP)
                .scheme("bearer")
                .bearerFormat("JWT")
                .description("JWT access token obtained via login");

        return new OpenAPI()
                .info(information)
                .addServersItem(server)
                .components(new Components().addSecuritySchemes("bearer-jwt", bearerScheme))
                .addSecurityItem(new SecurityRequirement().addList("bearer-jwt"));
    }

    @Bean
    public OpenApiCustomizer oauth2ApiCustomizer() {
        return (openAPI) -> {
            var authorization = new io.swagger.v3.oas.models.Operation()
                    .summary("Initiate OAuth2 login")
                    .description("Redirects the user to the OAuth2 provider (Google or GitHub) for authentication.")
                    .addTagsItem("Authentication")
                    .addParametersItem(new Parameter()
                            .name("registrationId")
                            .in("path")
                            .required(true)
                            .schema(new StringSchema()
                                    ._default("google")
                                    ._enum(List.of("google", "github")))
                            .description("OAuth2 provider registration ID"))
                    .responses(new ApiResponses()
                            .addApiResponse("302", new ApiResponse().description("Redirect to OAuth2 provider"))
                            .addApiResponse("400", new ApiResponse().description("Invalid registration ID")))
                    .security(List.of());

            var callback = new io.swagger.v3.oas.models.Operation()
                    .summary("OAuth2 callback")
                    .description("Handles the OAuth2 authorization code callback from the provider. " +
                            "On success, returns a JSON response with a JWT token.")
                    .addTagsItem("Authentication")
                    .addParametersItem(new Parameter()
                            .name("registrationId")
                            .in("path")
                            .required(true)
                            .schema(new StringSchema()
                                    ._default("google")
                                    ._enum(List.of("google", "github")))
                            .description("OAuth2 provider registration ID"))
                    .responses(new ApiResponses()
                            .addApiResponse("200", new ApiResponse()
                                    .description("OAuth2 login successful, returns JWT token")
                                    .content(new io.swagger.v3.oas.models.media.Content()
                                            .addMediaType("application/json", new io.swagger.v3.oas.models.media.MediaType()
                                                    .schema(new io.swagger.v3.oas.models.media.ObjectSchema()
                                                            .properties(Map.of("token",
                                                                    new StringSchema().description("JWT access token")))))))
                            .addApiResponse("401", new ApiResponse().description("OAuth2 authentication failed")))
                    .security(List.of());

            openAPI.path("/api/v1/auth/login/oauth2/authorization/{registrationId}",
                    new PathItem().get(authorization));
            openAPI.path("/api/v1/auth/login/oauth2/code/{registrationId}",
                    new PathItem().get(callback));
        };
    }

}
