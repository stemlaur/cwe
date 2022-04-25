package com.stemlaur.security;

public abstract class AbstractBusinessException extends RuntimeException {
    public AbstractBusinessException(String message) {
        super(message);
    }
}
