package com.lgellu.JwtSecurity.service.jwt;

import com.lgellu.JwtSecurity.exception.InvalidJwtException;
import com.lgellu.JwtSecurity.exception.JwtTokenExpiredException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
public class JwtService {
    private final SecretKey key;
    private final long jwtExpiration;
    private final JwtParser parser;

    public JwtService(JwtProperties jwtProperties) {
        byte[] decodedKey = Base64.getDecoder().decode(jwtProperties.getSecret());
        if (decodedKey.length < 32) {
            throw new IllegalArgumentException("JWT Secret must be at least 256 bits (32 bytes) after Base64 decoding");
        }
        this.key = Keys.hmacShaKeyFor(decodedKey);
        this.jwtExpiration = jwtProperties.getExpirationMs();
        this.parser = Jwts.parser()
                .verifyWith(key)
                .build();
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        if (userDetails instanceof UserDetailsImpl user)
            claims.put("version", user.getTokenVersion());
        claims.put("roles", userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList());
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(userDetails.getUsername())
                .claims(claims)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusMillis(jwtExpiration)))
                .signWith(key)
                .compact();
    }

    // Validate & Parse Token
    private Jws<Claims> validateToken(String token) {
        try {
            return parser.parseSignedClaims(token);
        } catch (ExpiredJwtException e) { // Catch the JJWT library exception
            log.error("JWT Expired: {}", e.getMessage());
            throw new JwtTokenExpiredException("JWT token has expired");
        } catch (JwtException | IllegalArgumentException e) { // Catch all other JWT errors
            log.error("JWT Invalid: {}", e.getMessage());
            throw new InvalidJwtException("Invalid JWT token");
        }
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            String username = extractUsername(token);
            int tokenVersion = extractTokenVersion(token);
            boolean flag = false;
            if (userDetails instanceof UserDetailsImpl user) {
                int currentVersion = user.getTokenVersion();
                flag = (tokenVersion == currentVersion);
            }
            return flag && username.equals(userDetails.getUsername());
        } catch (JwtTokenExpiredException | InvalidJwtException e) {
            return false;
        }
    }

    public String extractUsername(String token) {
        return validateToken(token).getPayload().getSubject();
    }

    public int extractTokenVersion(String token) {
        Object version = validateToken(token)
                .getPayload()
                .get("version");

        if (version instanceof Integer) {
            return (Integer) version;
        } else if (version instanceof Long) {
            return ((Long) version).intValue();
        }

        throw new InvalidJwtException("Invalid token version type");
    }
}
