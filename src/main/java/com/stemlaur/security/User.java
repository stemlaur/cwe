package com.stemlaur.security;

import static org.apache.commons.lang3.Validate.notNull;

/**
 * This class no longer has the 4 security problems.
 *
 * - CWE-476 - Cross-site Scripting
 * - CWE-20 - Improper Input Validation
 * - CWE-476 - NULL Pointer Dereference
 * - CWE-522 - Insufficiently Protected Credentials
 */
public final class User {
    private final Login login;
    private final Password password; // Domain primitives are used instead of raw String

    public User(final Login login, final Password password) {
        this.login = notNull(login, "The login should not be null"); // Null check to avoid CWE-476 - NULL Pointer Dereference
        this.password = notNull(password, "The password should not be null"); // Null check to avoid CWE-476 - NULL Pointer Dereference
    }

    public Login login() {
        return this.login;
    }

    public Password password() {
        return this.password;
    }

    @Override
    public String toString() {
        return "User{" +
                "login=" + login +
                ", password=" + password +
                '}';
    }
}