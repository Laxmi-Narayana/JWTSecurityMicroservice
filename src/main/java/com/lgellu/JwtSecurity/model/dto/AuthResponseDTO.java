package com.lgellu.JwtSecurity.model.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.Set;

@Getter
@Setter
@AllArgsConstructor
public class AuthResponseDTO {
    String username;
    String accessToken;
    Set<String> roles;
}
