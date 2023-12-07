package com.dailyon.apigatewayservice.Util;

import com.google.common.base.Function;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Key;

@Slf4j
@Component
public class JwtUtil {

    @Autowired
    private Environment environment;

    public Claims parse(String jwt) {
        return Jwts.parser().setSigningKey(Keys.hmacShaKeyFor(environment.getProperty("secretKey").getBytes())).parseClaimsJws(jwt).getBody();
    }

    private Integer getUserId(Claims claims) {
        return claims.get("userId", Integer.class);
    }

    private String getUserRole(Claims claims){
        return claims.get("userRole", String.class);
    }
    public void addJwtPayloadHeaders(ServerHttpRequest request, Claims claims) {
        System.out.println("페이로드 헤더 실행");
        Integer userId = getUserId(claims);
        String userRole = getUserRole(claims);
        request.mutate()
                .header("Content-Type", "application/json;charset=UTF-8")
                .header("memberId",String.valueOf(userId))
                .header("memberRole",String.valueOf(userRole))
                .build();
    }

    public void addJwtPayloadHeadersForProductService(ServerHttpRequest request, Claims claims) {
        Integer userId = (claims != null) ? getUserId(claims) : null;
        request.mutate()
                .header("Content-Type", "application/json;charset=UTF-8")
                .header("userId", String.valueOf(userId) == null ? null : String.valueOf(userId))
                .build();
    }
}