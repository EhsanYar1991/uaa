package com.mciws.uaa.controller;

import com.mciws.uaa.common.GeneralResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Arrays;
import java.util.stream.Collectors;

@RestControllerAdvice
public class RestExceptionHandler {

    @ExceptionHandler(value = Throwable.class)
    public ResponseEntity<GeneralResponse> exceptionHandler(Throwable throwable) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                new GeneralResponse(
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        Arrays.stream(throwable.getSuppressed()
                        ).map(Throwable::getMessage).collect(Collectors.toList())));
    }


}
