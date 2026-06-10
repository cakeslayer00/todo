package dev.cake.auth.common.exception;

public class DuplicateResourceException extends RuntimeException {

    public DuplicateResourceException(String field, String value) {
        super("%s '%s' already taken".formatted(field, value));
    }

}
