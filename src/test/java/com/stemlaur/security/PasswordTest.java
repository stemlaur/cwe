package com.stemlaur.security;

import com.stemlaur.security.Password.InvalidPassword;
import com.stemlaur.security.Password.PasswordAlreadyConsumed;
import org.apache.commons.lang3.NotImplementedException;
import org.junit.jupiter.api.Test;

import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PasswordTest {

    @Test
    void passwordValueCanBeReadOnce() {
        Password password = DataSet.validPassword();
        assertThat(String.valueOf(password.value()))
                .isEqualTo("m@sup3rPassw0rd");
    }

    @Test
    void instantiatingPasswordWithEmptyConstructorIsForbidden() {
        assertThatThrownBy(Password::new)
                .isInstanceOf(NotImplementedException.class)
                .hasMessage("Illegal call of empty constructor");
    }

    @Test
    void shouldFailWithNullInput() {
        assertThatThrownBy(() -> new Password(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("The password value should not be null");
    }

    @Test
    void shouldFailWithImproperLength() {
        assertThatThrownBy(() -> new Password("toosimple".toCharArray()))
                .isInstanceOf(InvalidPassword.class)
                .hasMessage("password length must be between 10 and 100 chars");

        final String inputTooLong = new String(new char[101]).replace('\0', ' ');
        assertThatThrownBy(() -> new Password(inputTooLong.toCharArray()))
                .isInstanceOf(InvalidPassword.class)
                .hasMessage("password length must be between 10 and 100 chars");
    }

    @Test
    void shouldFailWithPasswordValueTooSimple() {
        assertThatThrownBy(() -> new Password("weekPassword".toCharArray()))
                .isInstanceOf(InvalidPassword.class)
                .hasMessage("Illegal password format, does not respect policy");
    }

    @Test
    void passwordValueCannotBeReadMoreThatOnce() {
        Password password = DataSet.validPassword();
        password.value(); // read-once

        assertThatThrownBy(password::value)
                .isInstanceOf(PasswordAlreadyConsumed.class)
                .hasMessage("Password value has already been consumed");
    }

    @Test
    void passwordIsErasedForClientAfterInstantiation() {
        char[] passwordChars = "m@sup3rPassw0rd".toCharArray();

        new Password(passwordChars);

        assertThat(passwordChars).isEqualTo("000000000000000".toCharArray());
    }

    @Test
    void shouldFailOnSerialization() throws Exception {
        Path file = Files.createTempFile("pass", UUID.randomUUID().toString());

        try (FileOutputStream out = new FileOutputStream(file.toFile())) {
            try (ObjectOutputStream oos = new ObjectOutputStream(out)) {
                Password password = DataSet.validPassword();

                assertThatThrownBy(() -> oos.writeObject(password))
                        .isInstanceOf(UnsupportedOperationException.class)
                        .hasMessage("Serialization or de-serialization of passwords is not allowed");
            }
        }
    }

    @Test
    void shouldFailOnDeserialization() {
        Password password = DataSet.validPassword();
        assertThatThrownBy(() -> password.readExternal(null))
                .isInstanceOf(UnsupportedOperationException.class)
                .hasMessage("Serialization or de-serialization of passwords is not allowed");
    }
}