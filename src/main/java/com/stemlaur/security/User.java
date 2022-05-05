package com.stemlaur.security;

/**
 * This class has 4 security problems.
 *
 * See <a href="https://cwe.mitre.org/top25/archive/2021/2021_cwe_top25.html">https://cwe.mitre.org/top25/archive/2021/2021_cwe_top25.html</a>
 *
 * <p>
 * - CWE-79 - Cross-site Scripting <a href="https://cwe.mitre.org/data/definitions/79.html">https://cwe.mitre.org/data/definitions/79.html</a>
 * - CWE-20 - Improper Input Validation <a href="https://cwe.mitre.org/data/definitions/20.html">https://cwe.mitre.org/data/definitions/20.html</a>
 * - CWE-476 - NULL Pointer Dereference <a href="https://cwe.mitre.org/data/definitions/476.html">https://cwe.mitre.org/data/definitions/476.html</a>
 * - CWE-522 - Insufficiently Protected Credentials <a href="https://cwe.mitre.org/data/definitions/522.html">https://cwe.mitre.org/data/definitions/522.html</a>
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

