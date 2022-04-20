package com.stemlaur.security;

import org.apache.commons.lang3.builder.ToStringBuilder;

/**
 * This class has 4 security problems.
 *
 * - CWE-476 - Cross-site Scripting
 * - CWE-20 - Improper Input Validation
 * - CWE-476 - NULL Pointer Dereference
 * - CWE-522 - Insufficiently Protected Credentials
 */
public class User {
    private final String login;
    private final String password;

    public User(final String login, final String password) {
        this.login = login;
        this.password = password;
    }

    private String getLogin() {
        return this.login;
    }

    private String getPassword() {
        return this.password;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this)
                .toString();
    }
}