package com.stemlaur.security;

import static org.apache.commons.lang3.Validate.inclusiveBetween;
import static org.apache.commons.lang3.Validate.matchesPattern;
import static org.apache.commons.lang3.Validate.notNull;

/**
 * Validation should be executed in the following order:
 * <p>
 * - Length check: Is the input length within the expected boundaries?
 * - Lexical content chec: Does the input contain the right characters and encoding?
 * - Syntax chec: Is the input format right?
 */
public final class Login { // Domain primitive (or value object) representing a Login
    private final String value;

    public Login(final String value) {
        notNull(value, "The login value should not be null"); // Null check to avoid CWE-476 - NULL Pointer Dereference
        inclusiveBetween(3, 20, value.length(), "login length must be between 3 and 20 chars"); // Size validation to avoid DOS attacks and CWE-20 - Improper Input Validation
        matchesPattern(value.toLowerCase(), "^[a-z]+$", "Illegal login format, expecting only letters"); // Pattern matching to avoid CWE-476 - Cross-site Scripting
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
}