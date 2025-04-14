package com.sparta.limited.api_gateway.security.config;

import com.sparta.limited.api_gateway.security.filter.AuthWebFilter;
import com.sparta.limited.api_gateway.security.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity.CsrfSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.FormLoginSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.HttpBasicSpec;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtService jwtService;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(
        ServerHttpSecurity http
    ) {
        AuthWebFilter authWebFilter = new AuthWebFilter(jwtService);
        http
            .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
            .csrf(CsrfSpec::disable)
            .formLogin(FormLoginSpec::disable)
            .httpBasic(HttpBasicSpec::disable)
            .authorizeExchange(exchange -> exchange
                .pathMatchers(HttpMethod.POST,
                    "/api/v1/signup",
                    "/api/v1/login"
                ).permitAll()

                .pathMatchers(HttpMethod.GET,
                    "/api/v1/products/{productId}",
                    "/api/v1/auction-products/{auctionProductId}",
                    "/api/v1/auctions",
                    "/api/v1/auctions/{auctionId}",
                    "/api/v1/preuser-products/{preuserProductId}",
                    "/api/v1/preuser/events/{preuserId}",
                    "/api//v1/preuser",
                    "api/v1/limited-products/{limitedProductId}",
                    "api/v1/limited-events/{limitedEventId}",
                    "api/v1/limited-events"
                ).permitAll()

                .anyExchange().authenticated()
            )
            .addFilterBefore(authWebFilter, SecurityWebFiltersOrder.AUTHENTICATION);

        return http.build();
    }

}
