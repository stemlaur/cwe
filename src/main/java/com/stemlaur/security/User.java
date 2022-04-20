package com.stemlaur.security;

import lombok.Value;

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
@Value
public class User {
    String login;
    String password;
}

