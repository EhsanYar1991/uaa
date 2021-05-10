package com.mciws.uaa.models;

import java.io.Serializable;

public class AuthenticationResponse implements Serializable {

    private final String access_token;

    public AuthenticationResponse(String jwt) {
        this.access_token = jwt;
    }

    public String getAccess_token() {
        return access_token;
    }
}
