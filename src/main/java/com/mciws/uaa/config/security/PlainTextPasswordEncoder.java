package com.mciws.uaa.config.security;


import org.springframework.security.crypto.password.PasswordEncoder;

public final class PlainTextPasswordEncoder implements PasswordEncoder {



    public String encode(final String password) {
        return password;
    }

    @Override
    public String encode(CharSequence charSequence) {
        return String.valueOf(charSequence);
    }

    @Override
    public boolean matches(CharSequence charSequence, String s) {
        return String.valueOf(charSequence).equals(s);
    }
}
