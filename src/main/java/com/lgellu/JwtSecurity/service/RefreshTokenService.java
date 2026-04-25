package com.lgellu.JwtSecurity.service;

import com.lgellu.JwtSecurity.model.entity.RefreshToken;

public interface RefreshTokenService {
    RefreshToken createRefreshToken(String username);
    RefreshToken validateRefreshToken(String token);
    RefreshToken rotateRefreshToken(RefreshToken oldToken);
    void revokeRefreshToken(String token);
    void purgeExpiredTokens();
}
