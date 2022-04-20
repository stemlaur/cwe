package com.stemlaur.security;

public abstract class DataSet {
    private DataSet() {
    }

    public static Password validPassword() {
        return new Password("m@sup3rPassw0rd".toCharArray());
    }

    public static Login validUser() {
        return new Login("stemlaur");
    }
}
