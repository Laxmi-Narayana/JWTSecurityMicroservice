package com.lgellu.JwtSecurity.utils;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.MacAlgorithm;

import javax.crypto.SecretKey;
import java.util.Base64;

public class JwtSecretKey {
    public static void main(String[] args) {
        MacAlgorithm algorithm = Jwts.SIG.HS256;
        SecretKey secretKey = algorithm.key().build();
        String base64Key = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        System.out.println(base64Key);
    }
}
