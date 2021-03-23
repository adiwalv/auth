package com.adiwal.auth.exception;

import com.adiwal.commons.exceptions.AdiwalAuthException;
import com.adiwal.commons.exceptions.Error;
import com.adiwal.commons.exceptions.ExceptionUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(AdiwalAuthException.class)
    public ResponseEntity<Error> handleAdiwalAuthException(AdiwalAuthException e) {
        return ExceptionUtils.handleBadRequest(e);
    }
}
