package com.lgellu.JwtSecurity.service.impl;

import com.lgellu.JwtSecurity.enums.Role;
import com.lgellu.JwtSecurity.exception.InvalidRefreshTokenException;
import com.lgellu.JwtSecurity.exception.UserAlreadyExistsException;
import com.lgellu.JwtSecurity.model.dto.AuthResponseDTO;
import com.lgellu.JwtSecurity.model.entity.RefreshToken;
import com.lgellu.JwtSecurity.model.entity.User;
import com.lgellu.JwtSecurity.model.request.UserRequest;
import com.lgellu.JwtSecurity.repository.UserRepository;
import com.lgellu.JwtSecurity.service.AuthenticationService;
import com.lgellu.JwtSecurity.service.RefreshTokenService;
import com.lgellu.JwtSecurity.service.jwt.JwtProperties;
import com.lgellu.JwtSecurity.service.jwt.JwtService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    private static final String REFRESH_TOKEN_COOKIE = "refreshToken";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;
    private final RefreshTokenService refreshTokenService;

    @Override
    public String register(UserRequest userRequest) {
        if (userRepository.findByUsername(userRequest.getUsername()).isPresent()) {
            throw new UserAlreadyExistsException("user already exists: " + userRequest.getUsername());
        }
        User user = new User();
        user.setUsername(userRequest.getUsername());
        user.setPassword(passwordEncoder.encode(userRequest.getPassword()));
        user.setRoles(Set.of(Role.ROLE_USER));
        userRepository.save(user);
        return "user registered successfully";
    }

    @Override
    public AuthResponseDTO login(UserRequest userRequest, HttpServletResponse httpServletResponse) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        userRequest.getUsername(),
                        userRequest.getPassword()
                )
        );
        UserDetails userDetails = userDetailsService.loadUserByUsername(userRequest.getUsername());

        User user = userRepository.findByUsername(userRequest.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        user.setTokenVersion(user.getTokenVersion() + 1);
        userRepository.save(user);

        String accessToken = jwtService.generateToken(userDetails);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getUsername());
        setRefreshTokenCookie(refreshToken.getToken(), httpServletResponse);

        Set<String> roles = userDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
        return new AuthResponseDTO(userRequest.getUsername(), accessToken, roles);
    }

    @Override
    public AuthResponseDTO refresh(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        String token = extractRefreshTokenFromCookie(httpServletRequest);

        RefreshToken oldToken = refreshTokenService.validateRefreshToken(token);
        RefreshToken newToken = refreshTokenService.rotateRefreshToken(oldToken);

        setRefreshTokenCookie(newToken.getToken(), httpServletResponse);

        UserDetails userDetails = userDetailsService.loadUserByUsername(newToken.getUsername());
        String accessToken = jwtService.generateToken(userDetails);

        Set<String> roles = userDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
        return new AuthResponseDTO(newToken.getUsername(), accessToken, roles);
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        try {
            String token = extractRefreshTokenFromCookie(request);
            refreshTokenService.revokeRefreshToken(token);
        } catch (Exception e) {
            log.warn("Logout: Could not revoke token in DB, clearing cookie anyway.");
        } finally {
            clearRefreshTokenCookie(response);
        }
    }

    private void setRefreshTokenCookie(String token, HttpServletResponse response) {
        Cookie cookie = new Cookie(REFRESH_TOKEN_COOKIE, token);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/api/auth");
        cookie.setMaxAge((int) (jwtProperties.getRefreshExpirationMs() / 1000));
        response.addCookie(cookie);
    }

    private void clearRefreshTokenCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie(REFRESH_TOKEN_COOKIE, "");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/api/auth");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }

    private String extractRefreshTokenFromCookie(HttpServletRequest request) {
        if (request.getCookies() == null) {
            throw new InvalidRefreshTokenException("No cookies found in request");
        }
        return Arrays.stream(request.getCookies())
                .filter(c -> REFRESH_TOKEN_COOKIE.equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElseThrow(() -> new InvalidRefreshTokenException("Refresh token cookie not found"));
    }
}
