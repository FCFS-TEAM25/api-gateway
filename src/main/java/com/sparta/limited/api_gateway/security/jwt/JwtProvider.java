package com.sparta.limited.api_gateway.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import java.security.Key;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JwtProvider {

    private final JwtProperties jwtProperties;

    private Key key;

    @PostConstruct
    public void keyInit() {
        key = Keys.hmacShaKeyFor(jwtProperties.getSecretKey().getBytes());
    }

    public Claims getClaims(String token) {
        return Jwts.parserBuilder()
            .setSigningKey(key)
            .build()
            .parseClaimsJws(token)
            .getBody();
    }

    public void validateToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            throw new JwtException("토큰이 null 이거나 비어 있습니다");
        }
        try {
            getClaims(token);
        } catch (ExpiredJwtException e) {
            throw new JwtException("만료된 토큰입니다", e);
        } catch (JwtException e) {
            throw new JwtException("유효하지 않은 토큰입니다", e);
        }
    }

}
