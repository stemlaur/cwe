package com.stemlaur.security;

import org.junit.jupiter.api.Test;

import static com.stemlaur.security.DataSet.validUser;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("login length must be between 3 and 20 chars");

        final String inputTooLong = new String(new char[21]).replace('\0', ' ');

        assertThatThrownBy(() -> new Login(inputTooLong))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("login length must be between 3 and 20 chars");
    }

    @Test
    void shouldFailWithMaliciousInput() {
        assertInstantiationFails("'or%20select *");
        assertInstantiationFails("admin'--");
        assertInstantiationFails("<>\"'%;)(&+");
        assertInstantiationFails("0 or 1=1 --");
        assertInstantiationFails("<script");
        assertInstantiationFails("</script>");
    }

    private void assertInstantiationFails(String input) {
        assertThatThrownBy(() -> new Login(input))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Illegal login format, expecting only letters");
    }
}