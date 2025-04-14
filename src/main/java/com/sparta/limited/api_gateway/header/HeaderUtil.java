package com.sparta.limited.api_gateway.header;

import com.sparta.limited.api_gateway.info.UserInfo;
import org.springframework.web.server.ServerWebExchange;

public class HeaderUtil {

    public static ServerWebExchange createCustomHeader(
        ServerWebExchange exchange,
        UserInfo userInfo,
        String accessToken,
        String refreshToken
    ) {
        return exchange.mutate()
            .request(builder -> builder.headers(httpHeaders -> {
                httpHeaders.set("X-User-Id", userInfo.userId());
                httpHeaders.set("X-User-Name", userInfo.username());
                httpHeaders.set("X-User-Role", userInfo.role());
                httpHeaders.set("X-Access-Token", accessToken);
                httpHeaders.set("X-Refresh-Token", refreshToken);
            }))
            .build();
    }
}
