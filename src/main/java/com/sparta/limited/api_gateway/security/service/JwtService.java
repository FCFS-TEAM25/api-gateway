package com.sparta.limited.api_gateway.security.service;

import com.sparta.limited.api_gateway.info.UserInfo;
import com.sparta.limited.api_gateway.security.jwt.JwtProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JwtService {

    private static final String BEARER_PREFIX = "Bearer ";
    private final JwtProvider jwtProvider;

    public String getAccessToken(String authHeader) {
        if (!authHeader.startsWith(BEARER_PREFIX)) {
            throw new JwtException("Bearer 토큰이 아닙니다 받은 헤더 : " + authHeader);
        }
        return authHeader.substring(BEARER_PREFIX.length());
    }

    public void validateToken(String token) {
        jwtProvider.validateToken(token);
    }

    public UserInfo createUserInfo(String token) {
        Claims claims = jwtProvider.getClaims(token);
        return UserInfo.ofClaims(claims);
    }
}
