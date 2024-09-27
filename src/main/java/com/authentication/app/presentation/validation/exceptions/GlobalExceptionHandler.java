package com.authentication.app.presentation.validation.exceptions;

import java.util.Map;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.authentication.app.presentation.validation.exceptions.custom.UserNotEnableException;

import jakarta.mail.MessagingException;
import jakarta.persistence.NoResultException;

@ControllerAdvice
public class GlobalExceptionHandler {
    

    private static final String KEY = "error";

    @ExceptionHandler(MethodArgumentNotValidException.class)
    private ResponseEntity<Map<String, String>> handleValidationErrors(
        MethodArgumentNotValidException ex
    ) {

        String error = ex.getBindingResult()
                .getFieldErrors()
                .stream().map(FieldError::getDefaultMessage)
                .findFirst().orElse(ex.getMessage());

        return new ResponseEntity<>(Map.of(KEY, error), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(NoResultException.class)
    private ResponseEntity<Map<String, String>> handleEntityNotFound(NoResultException ex) {
        return new ResponseEntity<>(Map.of(KEY, ex.getMessage()), HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(JWTVerificationException.class)
    public ResponseEntity<Map<String, String>> handleDeniedAccessException(JWTVerificationException ex) {
        return new ResponseEntity<>(Map.of(KEY, ex.getMessage()), HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Map<String, String>> handleBadCredentialsException(BadCredentialsException ex) {
        return new ResponseEntity<>(Map.of(KEY, ex.getMessage()), HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(MessagingException.class)
    public ResponseEntity<Map<String, String>> handleSentEmailException(MessagingException ex) {
        return new ResponseEntity<>(Map.of(KEY, ex.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(UserNotEnableException.class)
    public ResponseEntity<Map<String, String>> handleUserNotEnableException(UserNotEnableException ex) {
        return new ResponseEntity<>(Map.of(KEY, ex.getMessage()), HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<Map<String, String>> handleDataIntegrityViolationException(DataIntegrityViolationException ex) {
        return new ResponseEntity<>(Map.of(KEY, ex.getMessage()), HttpStatus.BAD_REQUEST);
    }
}
