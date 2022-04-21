package com.stemlaur.security;

/**
 * This class has 4 security problems.
 *
 * See https://cwe.mitre.org/top25/archive/2021/2021_cwe_top25.html
 *
 * <p>
 * - CWE-79 - Cross-site Scripting https://cwe.mitre.org/data/definitions/79.html
 * - CWE-20 - Improper Input Validation https://cwe.mitre.org/data/definitions/20.html
 * - CWE-476 - NULL Pointer Dereference https://cwe.mitre.org/data/definitions/476.html
 * - CWE-522 - Insufficiently Protected Credentials https://cwe.mitre.org/data/definitions/522.html
 */
public class User {
    private final String login;
    private final String password;

    public User(String login, String password) {
        this.login = login;
        this.password = password;
    }

    public String getLogin() {
        return login;
    }

    public String getPassword() {
        return password;
    }

    @Override
    public String toString() {
        return "User{" +
                "login='" + login + '\'' +
                ", password='" + password + '\'' +
                '}';
    }
}

