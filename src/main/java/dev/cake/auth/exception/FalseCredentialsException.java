package dev.cake.auth.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class FalseCredentialsException extends RuntimeException {

    public FalseCredentialsException() {
        super("User with provided credentials doesn't exist");
    }

}
