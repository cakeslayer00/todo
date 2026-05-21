package dev.cake.auth.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@Tag(name = "Home")
public class HomeController {

    @GetMapping("/")
    @Operation(summary = "Greet authenticated user", description = "Returns a greeting with the authenticated user's name")
    @ApiResponse(responseCode = "200", description = "Greeting returned successfully")
    public String home(Principal principal) {
        return "Hello, " + principal.getName();
    }

}
