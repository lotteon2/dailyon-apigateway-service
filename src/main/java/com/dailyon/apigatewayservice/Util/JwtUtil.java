package com.dailyon.apigatewayservice.Util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class JwtUtil {

  @Autowired private Environment environment;

  @Value("${secretKey}")
  private String key;

  @Value("${chatSecretKey}")
  private String chatKey;

  public Claims parse(String jwt, boolean isChatRequest) {
    return Jwts.parser()
        .setSigningKey(Keys.hmacShaKeyFor(isChatRequest ? chatKey.getBytes() : key.getBytes()))
        .parseClaimsJws(jwt)
        .getBody();
  }

  private Long getMemberId(Claims claims) {
    return claims.get("memberId", Long.class);
  }

  private String getUserRole(Claims claims) {
    return claims.get("role", String.class);
  }

  public void addJwtPayloadHeaders(ServerHttpRequest request, Claims claims) {
    Long memberId = getMemberId(claims);
    String userRole = getUserRole(claims);
    request
        .mutate()
        .header("Content-Type", "application/json;charset=UTF-8")
        .header("memberId", String.valueOf(memberId))
        .header("role", String.valueOf(userRole))
        .build();
  }
}
