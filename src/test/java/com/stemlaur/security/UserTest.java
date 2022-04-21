package com.stemlaur.security;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class UserTest {

    @Test
    void toStringIsDangerous() {
        User user = new User("stemlaur", "myweakpassword");

        // far away in another part of the code
        assertThat(user.toString()).isEqualTo("User{login='stemlaur', password='myweakpassword'}");
        System.out.println("Ouups the client accidentally logged the user and its password : " + user);
    }

    @Test
    void nullInputAreAccepted() {
        User user = new User(null, null);
        assertThat(user.toString()).isEqualTo("User{login='null', password='null'}");

        // far away in another part of the codegit
        System.out.println(user.getLogin().toUpperCase());
    }

    @Test
    void clientKeepReferenceToThePassword() {
        String password = "myweakpassword";

        new User("stemlaur", password);

        System.out.println("Ouups the client accidentally logged the referenced password : " + password);
    }

    @Test
    void injectJavaScriptInLoginIsAccepted() {
        User user = new User("<script language=\"javascript\">alert(\"You've been attacked!\");</script>", "myweakpassword");

        System.out.println("<html><body>" + user + "</body></html>");
    }

    @Test
    void distionariesAreAcceptedInIput() {
        String thousandCharsLogin = "Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean commodo ligula eget dolor. Aenean massa. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Donec quam felis, ultricies nec, pellentesque eu, pretium quis, sem. Nulla consequat massa quis enim. Donec pede justo, fringilla vel, aliquet nec, vulputate eget, arcu. In enim justo, rhoncus ut, imperdiet a, venenatis vitae, justo. Nullam dictum felis eu pede mollis pretium. Integer tincidunt. Cras dapibus. Vivamus elementum semper nisi. Aenean vulputate eleifend tellus. Aenean leo ligula, porttitor eu, consequat vitae, eleifend ac, enim. Aliquam lorem ante, dapibus in, viverra quis, feugiat a, tellus. Phasellus viverra nulla ut metus varius laoreet. Quisque rutrum. Aenean imperdiet. Etiam ultricies nisi vel augue. Curabitur ullamcorper ultricies nisi. Nam eget dui. Etiam rhoncus. Maecenas tempus, tellus eget condimentum rhoncus, sem quam semper libero, sit amet adipiscing sem neque sed ipsum. Nam quam nunc, blandit vel, luctus pulvinar, hendrerit id, lorem. Maecenas nec odio et ante tincidunt tempus. Donec vitae sapien ut libero venenatis faucibus. Nullam quis ante. Etiam sit amet orci eget eros faucibus tincidunt. Duis leo. Sed fringilla mauris sit amet nibh. Donec sodales sagittis magna. Sed consequat, leo eget bibendum sodales, augue velit cursus nunc";
        User user = new User(thousandCharsLogin, "myweakpassword");

        System.out.println(user);
    }
}