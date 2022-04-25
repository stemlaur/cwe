package com.stemlaur.security;

import java.util.regex.Pattern;

import static org.apache.commons.lang3.Validate.notNull;

/**
 * Validation should be executed in the following order:
 * <p>
 * - Length check: Is the input length within the expected boundaries?
 * - Lexical content check: Does the input contain the right characters and encoding?
 * - Syntax check: Is the input format right?
 */
public final class Login { // Domain primitive (or value object) representing a Login
    private final String value;

    public Login(final String value) {
        notNull(value, "The login value should not be null"); // Null check to avoid CWE-476 - NULL Pointer Dereference
        checkLength(value.length()); // Size validation to avoid DOS attacks and CWE-20 - Improper Input Validation
        checkPattern(value.toLowerCase()); // Pattern matching to avoid CWE-476 - Cross-site Scripting
        this.value = value.toLowerCase();
    }

    public String value() {
        return value;
    }

    @Override
    public String toString() {
        return "Login{" +
                "value='" + value + '\'' +
                '}';
    }

    public static class InvalidLogin extends AbstractBusinessException {
        public InvalidLogin(final String message) {
            super(message);
        }

    }

    private static void checkLength(long value) {
        if (value < (long) 3 || value > (long) 20) {
            throw new InvalidLogin("login length must be between 3 and 20 chars");
        }
    }

    private static void checkPattern(CharSequence input) {
        if (!Pattern.matches("^[a-z]+$", input)) {
            throw new InvalidLogin("Illegal login format, expecting only letters");
        }
    }
}