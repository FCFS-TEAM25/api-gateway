package com.sparta.limited.api_gateway.header;

import io.jsonwebtoken.JwtException;
import org.springframework.web.server.ServerWebExchange;

public class CookieUtil {

    public static String getCookie(ServerWebExchange exchange, String name) {
        var cookies = exchange.getRequest().getCookies().get(name);
        if (cookies == null || cookies.isEmpty()) {
            throw new JwtException(name + " 쿠키가 없습니다");
        }
        return cookies.get(0).getValue();
    }

}
