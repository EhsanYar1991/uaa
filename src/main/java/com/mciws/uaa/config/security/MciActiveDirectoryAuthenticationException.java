package com.mciws.uaa.config.security;

import org.springframework.security.core.AuthenticationException;

public final class MciActiveDirectoryAuthenticationException extends AuthenticationException {

    private final String dataCode;

    MciActiveDirectoryAuthenticationException(String dataCode, String message, Throwable cause) {
        super(message, cause);
        this.dataCode = dataCode;
    }

    public String getDataCode() {
        return this.dataCode;
    }

}
