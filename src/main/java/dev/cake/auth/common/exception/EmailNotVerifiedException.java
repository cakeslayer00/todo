package dev.cake.auth.common.exception;

public class EmailNotVerifiedException extends RuntimeException {

    public EmailNotVerifiedException() {
        super("Email address must be verified to perform this action");
    }

}
