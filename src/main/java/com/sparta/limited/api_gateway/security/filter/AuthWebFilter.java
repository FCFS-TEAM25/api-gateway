package com.sparta.limited.api_gateway.security.filter;

import com.sparta.limited.api_gateway.header.CookieUtil;
import com.sparta.limited.api_gateway.header.HeaderUtil;
import com.sparta.limited.api_gateway.info.UserInfo;
import com.sparta.limited.api_gateway.security.service.JwtService;
import io.jsonwebtoken.JwtException;
import java.util.Collections;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@RequiredArgsConstructor
public class AuthWebFilter implements WebFilter {

    private final JwtService jwtService;

    @Override
    @NonNull
    public Mono<Void> filter(
        ServerWebExchange exchange,
        @NonNull WebFilterChain chain
    ) {
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null) {
            return chain.filter(exchange);
        }

        String accessToken = jwtService.getAccessToken(authHeader);
        String refreshToken = CookieUtil.getCookie(exchange, "refreshToken");

        try {
            jwtService.validateToken(accessToken);
            jwtService.validateToken(refreshToken);
        } catch (JwtException e) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        UserInfo userInfo = jwtService.createUserInfo(accessToken);

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
            userInfo.username(),
            null,
            Collections.singletonList(new SimpleGrantedAuthority(userInfo.role()))
        );
        authenticationToken.setDetails(userInfo.userId());

        SecurityContext securityContext = new SecurityContextImpl(authenticationToken);
        ServerWebExchange mutatedExchange = HeaderUtil.createCustomHeader(exchange, userInfo,
            accessToken, refreshToken);

        return chain.filter(mutatedExchange)
            .contextWrite(
                ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext)));
    }

}
