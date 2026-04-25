package com.lgellu.JwtSecurity.controller;

import com.lgellu.JwtSecurity.model.dto.AuthResponseDTO;
import com.lgellu.JwtSecurity.model.request.UserRequest;
import com.lgellu.JwtSecurity.service.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthenticationController {
    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody @Valid UserRequest userRequest) {
        return ResponseEntity.ok(authenticationService.register(userRequest));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDTO> login(@RequestBody @Valid UserRequest userRequest, HttpServletResponse httpServletResponse) {
        return ResponseEntity.ok(authenticationService.login(userRequest, httpServletResponse));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponseDTO> refresh(HttpServletRequest request, HttpServletResponse response) {
        return ResponseEntity.ok(authenticationService.refresh(request, response));
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request, HttpServletResponse response) {
        authenticationService.logout(request, response);
        return ResponseEntity.ok("User logged out successfully");
    }
}