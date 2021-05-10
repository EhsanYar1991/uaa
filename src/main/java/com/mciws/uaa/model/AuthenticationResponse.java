package com.mciws.uaa.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;

public class AuthenticationResponse implements Serializable {

    @JsonProperty("access_token")
    private final String accessToken;

    public AuthenticationResponse(String jwt) {
        this.accessToken = jwt;
    }

    public String getAccessToken() {
        return accessToken;
    }
}
