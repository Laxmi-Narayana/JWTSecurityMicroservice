package com.lgellu.JwtSecurity.exception;

public class InvalidJwtException extends RuntimeException{
    public InvalidJwtException(String message) {
        super(message);
    }
}
