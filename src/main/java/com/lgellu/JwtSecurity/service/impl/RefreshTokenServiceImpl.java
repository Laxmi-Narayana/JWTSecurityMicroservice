package com.lgellu.JwtSecurity.service.impl;

import com.lgellu.JwtSecurity.exception.InvalidRefreshTokenException;
import com.lgellu.JwtSecurity.model.entity.RefreshToken;
import com.lgellu.JwtSecurity.model.entity.User;
import com.lgellu.JwtSecurity.repository.RefreshTokenRepository;
import com.lgellu.JwtSecurity.repository.UserRepository;
import com.lgellu.JwtSecurity.service.RefreshTokenService;
import com.lgellu.JwtSecurity.service.jwt.JwtProperties;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtProperties jwtProperties;
    private final UserRepository userRepository;

    @Transactional
    @Override
    public RefreshToken createRefreshToken(String username) {
        refreshTokenRepository.deleteByUsername(username);
        RefreshToken refreshToken = RefreshToken.builder()
                .token(UUID.randomUUID().toString())
                .username(username)
                .expiresAt(Instant.now().plusMillis(jwtProperties.getRefreshExpirationMs()))
                .revoked(false)
                .build();
        return refreshTokenRepository.save(refreshToken);
    }

    @Transactional
    @Override
    public RefreshToken validateRefreshToken(String token) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new InvalidRefreshTokenException("Refresh token not found"));

        if (refreshToken.isRevoked()) {
            refreshTokenRepository.deleteByUsername(refreshToken.getUsername());
            throw new InvalidRefreshTokenException("Refresh token reuse detected - all sessions revoked");
        }

        if (refreshToken.getExpiresAt().isBefore(Instant.now())) {
            refreshTokenRepository.deleteByUsername(refreshToken.getUsername());
            throw new InvalidRefreshTokenException("Refresh token has expired - please login again");
        }
        return refreshToken;
    }

    @Transactional
    @Override
    public RefreshToken rotateRefreshToken(RefreshToken oldToken) {
        oldToken.setRevoked(true);
        oldToken.setRevokedAt(Instant.now());
        refreshTokenRepository.save(oldToken);

        User user = userRepository.findByUsername(oldToken.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        user.setTokenVersion(user.getTokenVersion() + 1);
        userRepository.save(user);
        return createRefreshToken(oldToken.getUsername());
    }

    @Transactional
    @Override
    public void revokeRefreshToken(String token) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new InvalidRefreshTokenException("Refresh token not found"));
        refreshToken.setRevoked(true);
        refreshToken.setRevokedAt(Instant.now());
        User user = userRepository.findByUsername(refreshToken.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        user.setTokenVersion(user.getTokenVersion() + 1);
        userRepository.save(user);
        refreshTokenRepository.save(refreshToken);
    }

    @Scheduled(cron = "0 0 2 * * ?") // Runs at 2 AM every day
    @Transactional
    @Override
    public void purgeExpiredTokens() {
        log.info("Starting scheduled purge of expired/revoked tokens");
        refreshTokenRepository.purgeInvalidTokens(Instant.now());
    }
}
