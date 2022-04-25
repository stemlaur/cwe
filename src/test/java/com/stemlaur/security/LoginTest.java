package com.stemlaur.security;

import com.stemlaur.security.Login.InvalidLogin;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.util.stream.Stream;

import static com.stemlaur.security.DataSet.validUser;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

class LoginTest {

    @Test
    void shouldReturnValue() {
        Login stemlaur = validUser();
        assertThat(stemlaur.value()).isEqualTo("stemlaur");
    }

    @Test
    void shouldFailWithNullInput() {
        assertThatThrownBy(() -> new Login(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("The login value should not be null");
    }

    @Test
    void shouldFailWithImproperLength() {
        assertThatThrownBy(() -> new Login("a"))
                .isInstanceOf(InvalidLogin.class)
                .hasMessage("login length must be between 3 and 20 chars");

        final String inputTooLong = new String(new char[21]).replace('\0', ' ');

        assertThatThrownBy(() -> new Login(inputTooLong))
                .isInstanceOf(InvalidLogin.class)
                .hasMessage("login length must be between 3 and 20 chars");
    }

    @TestFactory
    Stream<DynamicTest> shouldFailWithMaliciousInput() {
        return Stream.of(
                        "'or%20select *",
                        "admin'--",
                        "<>\"'%;)(&+",
                        "'%20or%20''='",
                        "'%20or%20'x'='x",
                        "\"%20or%20\"x\"=\"x",
                        "')%20or%20('x'='x",
                        "0 or 1=1 --",
                        "' or 0=0 --",
                        "\" or 0=0 --",
                        "<script",
                        "</script>"
                )
                .map(input -> dynamicTest("ShouldFailWithMaliciousInput: " + input, () -> assertThatThrownBy(() -> new Login(input))
                        .isInstanceOf(InvalidLogin.class)
                        .hasMessage("Illegal login format, expecting only letters")));
    }
}
