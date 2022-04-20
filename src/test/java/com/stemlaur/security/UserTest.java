package com.stemlaur.security;

import org.junit.jupiter.api.Test;

import static com.stemlaur.security.DataSet.validPassword;
import static com.stemlaur.security.DataSet.validUser;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class UserTest {

    @Test
    void shouldInstantiateProperUser() {
        User user = new User(validUser(), validPassword());
        assertThat(user.login()).isNotNull();
        assertThat(user.password()).isNotNull();
    }

    @Test
    void shouldNotBeInstantiatedWithNullParams() {
        assertThatThrownBy(() -> new User(validUser(), null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("The password should not be null");

        assertThatThrownBy(() -> new User(null, validPassword()))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("The login should not be null");
    }

    @Test
    void toStringDoesNotLeakSensitiveData() {
        User user = new User(validUser(), validPassword());
        assertThat(user.toString())
                .isEqualTo("User{login=Login{value='stemlaur'}, password=Password{value=*****}}");
    }
}