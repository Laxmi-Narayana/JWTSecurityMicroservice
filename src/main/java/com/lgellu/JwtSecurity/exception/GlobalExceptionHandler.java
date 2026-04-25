package com.lgellu.JwtSecurity.exception;

import com.lgellu.JwtSecurity.model.dto.ErrorResponseDTO;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.NoHandlerFoundException;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<ErrorResponseDTO> handleUserAlreadyExists(UserAlreadyExistsException ex) {
        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(buildError(HttpStatus.CONFLICT, "User already exists", "ALIAS EXISTS"));
    }

    @ExceptionHandler(JwtTokenExpiredException.class)
    public ResponseEntity<ErrorResponseDTO> handleExpired(JwtTokenExpiredException ex) {
        log.warn("Jwt Token expired: {}", ex.getMessage());

        return ResponseEntity.status(HttpStatus.GONE)
                .body(buildError(HttpStatus.GONE, "Jwt Token expired", "JWT_TOKEN_EXPIRED"));
    }

    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<ErrorResponseDTO> handleNoHandlerFound(NoHandlerFoundException ex) {
        log.warn("No handler found: {}", ex.getRequestURL());

        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(buildError(HttpStatus.NOT_FOUND, "API not found", "API_NOT_FOUND"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponseDTO> handleGeneric(Exception ex) {
        log.error("Unhandled exception", ex);

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(buildError(HttpStatus.INTERNAL_SERVER_ERROR, "Internal server error", "INTERNAL_ERROR"));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponseDTO> handleValidation(MethodArgumentNotValidException ex) {

        Map<String, String> errors = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .collect(Collectors.toMap(
                        FieldError::getField,
                        fe -> fe.getDefaultMessage() != null ? fe.getDefaultMessage() : "Invalid value",
                        (existing, replacement) -> existing
                ));

        log.warn("Validation failed: {}", errors);

        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(buildError(HttpStatus.BAD_REQUEST, "Validation failed", "VALIDATION_FAILED", errors));
    }

    @ExceptionHandler(InvalidRefreshTokenException.class)
    public ResponseEntity<ErrorResponseDTO> handleInvalidRefreshToken(InvalidRefreshTokenException ex) {
        log.warn("Invalid refresh token: {}", ex.getMessage());

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(buildError(HttpStatus.UNAUTHORIZED, ex.getMessage(), "INVALID_REFRESH_TOKEN"));
    }

    @ExceptionHandler(InvalidJwtException.class)
    public ResponseEntity<ErrorResponseDTO> handleInvalidJwt(InvalidJwtException ex) {
        log.warn("Invalid JWT: {}", ex.getMessage());

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(buildError(HttpStatus.UNAUTHORIZED, "Invalid authentication token", "INVALID_JWT"));
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ErrorResponseDTO> handleMethodNotSupported(HttpRequestMethodNotSupportedException ex) {
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED)
                .body(buildError(
                        HttpStatus.METHOD_NOT_ALLOWED,
                        "Method not allowed. Please use POST for this endpoint.",
                        "METHOD_NOT_ALLOWED"
                ));
    }

    private ErrorResponseDTO buildError(HttpStatus status, String message, String errorCode) {
        return ErrorResponseDTO.builder()
                .timestamp(LocalDateTime.now())
                .status(status.value())
                .error(status.getReasonPhrase())
                .message(message)
                .errorCode(errorCode)
                .build();
    }

    private ErrorResponseDTO buildError(HttpStatus status, String message, String errorCode, Map<String, String> validationErrors) {
        return ErrorResponseDTO.builder()
                .timestamp(LocalDateTime.now())
                .status(status.value())
                .error(status.getReasonPhrase())
                .message(message)
                .errorCode(errorCode)
                .validationErrors(validationErrors)
                .build();
    }
}
