package com.dailyon.apigatewayservice.Filter;

import com.dailyon.apigatewayservice.Util.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
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

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Component
public class NonAuthFilter extends AbstractGatewayFilterFactory<NonAuthFilter.Config> {
    private final JwtUtil jwtUtil;

    public static class Config {

    }

    public NonAuthFilter(JwtUtil jwtUtil) {
        super(Config.class);
        this.jwtUtil = jwtUtil;
    }

    @Override
    public GatewayFilter apply(NonAuthFilter.Config config) {
        return ((exchange, chain) -> {

            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            HttpHeaders headers = request.getHeaders();
            String authorizationHeader = headers.getFirst(HttpHeaders.AUTHORIZATION);

            try {
                if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {

                    String token = authorizationHeader.substring(7);
                    Claims claims = jwtUtil.parse(token, false);

                    if (isExpired(claims)) {
                        return onError(response, HttpStatus.UNAUTHORIZED);
                    }

                    jwtUtil.addJwtPayloadHeaders(request, claims);

                    return chain.filter(exchange);
                }
            }  catch (ExpiredJwtException e) {
                return onError(response, HttpStatus.UNAUTHORIZED, "JWT Token Expired");
            } catch (Exception e) {
                log.error("Error while processing JWT Token", e);
                return onError(response, HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error");
            }
            return chain.filter(exchange);
        });
    }

    private boolean isExpired(Claims claims) {
        return claims.getExpiration().getTime() < System.currentTimeMillis();
    }

    private Mono<Void> onError(ServerHttpResponse response, HttpStatus status, String errorMessage) {
        response.setStatusCode(status);
        String errorBody = "{\"error\": \"" + errorMessage + "\"}";
        DataBuffer buffer = response.bufferFactory().wrap(errorBody.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

    private Mono<Void> onError(ServerHttpResponse response, HttpStatus status) {
        response.setStatusCode(status);
        return response.setComplete();
    }
}
