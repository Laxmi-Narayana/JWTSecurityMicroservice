package com.lgellu.JwtSecurity.service;

import com.lgellu.JwtSecurity.model.dto.AuthResponseDTO;
import com.lgellu.JwtSecurity.model.request.UserRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface AuthenticationService {
    String register(UserRequest userRequest);
    AuthResponseDTO login(UserRequest userRequest, HttpServletResponse httpServletResponse);
    AuthResponseDTO refresh(HttpServletRequest request, HttpServletResponse httpServletResponse);
    void logout(HttpServletRequest request, HttpServletResponse response);
}
