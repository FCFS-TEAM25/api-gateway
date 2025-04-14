package com.sparta.limited.api_gateway.info;

import io.jsonwebtoken.Claims;

public record UserInfo(
    String userId,
    String username,
    String role
) {

    public static UserInfo ofClaims(Claims claims) {
        return new UserInfo(
            claims.getSubject(),
            claims.get("username", String.class),
            claims.get("role", String.class)
        );
    }
}
