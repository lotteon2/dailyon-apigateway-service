package com.dailyon.apigatewayservice.Filter;

import com.dailyon.apigatewayservice.Util.JwtUtil;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.CookieValue;
import reactor.core.publisher.Mono;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@Component
public class AuthFilter extends AbstractGatewayFilterFactory<AuthFilter.Config> {
    private final JwtUtil jwtUtil;

    public static class Config {

    }

    public AuthFilter(JwtUtil jwtUtil) {
        super(Config.class);
        this.jwtUtil = jwtUtil;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            if(!containsAuthorization(request)) {
                return onError(response, HttpStatus.UNAUTHORIZED);
            }
            MultiValueMap<String, HttpCookie> cookies = request.getCookies();
            List<HttpCookie> userInfoCookies = cookies.get("userInfo");

            List<String> jwtValues = userInfoCookies.stream()
                    .map(HttpCookie::getValue)
                    .collect(Collectors.toList());

            Claims claims = jwtUtil.parse(jwtValues.get(0));

            if(isExpired(claims)) {
                return onError(response, HttpStatus.UNAUTHORIZED);
            }

            jwtUtil.addJwtPayloadHeaders(request, claims);

            return chain.filter(exchange);
        });
    }

    private boolean containsAuthorization(ServerHttpRequest request) {
        if (request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
            return true;
        }
        HttpHeaders headers = request.getHeaders();

        List<String> cookieHeaders = headers.get(HttpHeaders.COOKIE);


        request.getCookies().containsKey("userInfo");

        if (cookieHeaders != null) {
            for (String cookieHeader : cookieHeaders) {
                if (cookieHeader.contains("userInfo")) {;
                    return true;
                }
            }
        }

        String cookieHeader = request.getHeaders().getFirst(HttpHeaders.COOKIE);

        return cookieHeader != null && cookieHeader.contains("userInfo");
    }

    private boolean isExpired(Claims claims) {
        return claims.getExpiration().getTime() < System.currentTimeMillis();
    }

    private String getJwt(ServerHttpRequest request) {
        return request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0).replace("Bearer", "");
    }

    private Mono<Void> onError(ServerHttpResponse response, HttpStatus status) {
        response.setStatusCode(status);
        return response.setComplete();
    }
}
