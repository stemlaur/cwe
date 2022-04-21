package com.stemlaur.security;

import org.apache.commons.lang3.NotImplementedException;

import java.io.Externalizable;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Arrays;

import static org.apache.commons.lang3.Validate.inclusiveBetween;
import static org.apache.commons.lang3.Validate.matchesPattern;
import static org.apache.commons.lang3.Validate.notNull;
import static org.apache.commons.lang3.Validate.validState;

/**
 * Password is called a **Read-once object** : a read-once object is, as the name implies, an object designed to be read once.
 *
 * This object usually represents a value or concept in your domain that’s considered to be **sensitive** (for example, passport numbers, credit card numbers, or passwords).
 *
 * The main purpose of the read-once object is to facilitate detection of unintentional use of the data it encapsulates.
 *
 * Often this object is a domain primitive, but you can apply this pattern to both entities and aggregates as well. The basic idea is that once the object has been created, it’s only possible to retrieve the data it encapsulates **once**. Trying to retrieve it more than once results in an error. The object also makes a reasonable effort to prevent the sensitive data from being extracted through serialization :
 *
 * - The password object implements the java.io.Externalizable interface and always throws an exception in order to prevent accidental serialization.
 *      An Externalizable class is one which handles its own Serialization and deserialization.
 *      During deserialization, the first step in the process is a default instantiation using the class' no-argument constructor.
 *      Therefore an Externalizable class without a no-arg constructor cannot be deserialized.
 *
 *      https://www.baeldung.com/java-externalizable
 *
 * - The value field is declared transient in case some library uses field access to serialize the object rather than Java serialization (but still honors the transient keyword).
 * - As a last measure, the toString method is implemented so it doesn’t output the actual value.
 *
 * This class avoids CWE-522 - Insufficiently Protected Credentials
 */
public final class Password implements Externalizable {
    private transient final char[] value; // The field is mark as transient
    private boolean consumed = false;

    // "Externalizable" classes should have no-arguments constructors
    // See https://rules.sonarsource.com/java/RSPEC-2060
    public Password() {
        throw new NotImplementedException("Illegal call of empty constructor");
    }

    public Password(final char[] value) { // Passing a char[] instead of a String, char array can be erased by the class
        this.value = validate(value).clone();
        Arrays.fill(value, '0'); // After consumption, we erase the value
    }

    public synchronized char[] value() { // Getting a value is synchronized to prevent thread interference
        validState(!consumed, "Password value has already been consumed");
        // The value can be consumed only once, this allows to detect when another part of the system tries to consume it by accident
        consumed = true;
        return value.clone();
    }

    @Override
    public String toString() {
        return "Password{value=*****}"; // We override toString to be sure that the password is not printed
    }

    @Override
    public void writeExternal(final ObjectOutput out) {
        deny(); // We forbid serialization of this object !
    }

    @Override
    public void readExternal(final ObjectInput in) {
        deny(); // We forbid serialization of this object !
    }

    private static void deny() {
        throw new UnsupportedOperationException(
                "Serialization or de-serialization of passwords is not allowed");
    }

    private static char[] validate(final char[] value) {
        // We validate the password :
        // Null check to avoid NULL Pointer Dereference
        // Size validation to avoid DOS attacks
        // Pattern matching to avoid Cross-site Scripting
        notNull(value, "The password value should not be null");
        inclusiveBetween(10, 100, value.length, "password length must be between 10 and 100 chars");
        matchesPattern(new String(value), "^(?=^.{8,}$)(?=.*\\d)(?=.*\\W+)(?![.\\n])(?=.*[A-Z])(?=.*[a-z]).*$",
                "Illegal password format, does not respect policy");
        return value;
    }
}