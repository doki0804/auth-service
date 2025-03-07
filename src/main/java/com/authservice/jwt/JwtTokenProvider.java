package com.authservice.jwt;

import com.authservice.entity.User;
import io.jsonwebtoken.*;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtTokenProvider {

    private final String jwtSecret = "$jwt.secret";
    private final long accessTokenValidity = 15 * 60 * 1000;
    private final long refreshTokenValidity = 7 * 24 * 60 * 60 * 1000;

    // Access Token 생성
    public String generateAccessToken(User user) {
        return Jwts.builder()
                .setSubject(user.getUserId())
                .claim("roles", user.getRoles())
                .claim("subscription", user.getSubscriptionStatus())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + accessTokenValidity))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    // Refresh Token 생성
    public String generateRefreshToken(User user) {
        return Jwts.builder()
                .setSubject(user.getUserId())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + refreshTokenValidity))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    // 토큰 검증
    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    // 토큰에서 아이디 추출
    public String getUserIdFromToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody().getSubject();
    }

    // 토큰 만료일 조회
    public Date getExpiration(String token) {
        try {
            return Jwts.parser().setSigningKey(jwtSecret)
                    .parseClaimsJws(token)
                    .getBody().getExpiration();
        } catch (Exception e) {
            return new Date(0);
        }
    }
}
