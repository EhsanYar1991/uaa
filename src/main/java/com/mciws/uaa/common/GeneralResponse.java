package com.mciws.uaa.common;

import org.springframework.http.HttpStatus;

import java.util.List;

public class GeneralResponse<T> {
    private HttpStatus status;
    private List<String> errorList;
    private T body;

    public GeneralResponse(T body) {
        this.body = body;
    }

    public GeneralResponse(HttpStatus status, T body) {
        this.status = status;
        this.body = body;
    }

    public GeneralResponse(HttpStatus status, List<String> errorList, T body) {
        this.status = status;
        this.errorList = errorList;
        this.body = body;
    }

    public GeneralResponse(HttpStatus status, List<String> errorList) {
        this.status = status;
        this.errorList = errorList;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public void setStatus(HttpStatus status) {
        this.status = status;
    }

    public List<String> getErrorList() {
        return errorList;
    }

    public void setErrorList(List<String> errorList) {
        this.errorList = errorList;
    }

    public T getBody() {
        return body;
    }

    public void setBody(T body) {
        this.body = body;
    }
}
