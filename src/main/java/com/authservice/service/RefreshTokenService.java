package com.authservice.service;

import com.authservice.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RedisTemplate<String, String> redisTemplate;
    private final JwtTokenProvider jwtTokenProvider;

    public void saveRefreshToken(String accessToken, String refreshToken) {
        String key = "refresh:" + accessToken;
        Date tokenExpiration = jwtTokenProvider.getExpiration(refreshToken);
        long refreshTokenValiditySeconds = tokenExpiration.getTime() / 1000;
        redisTemplate.opsForValue().set(key, refreshToken, refreshTokenValiditySeconds, TimeUnit.SECONDS);
    }

    // Redis에서 refresh token 조회
    public String getRefreshToken(String accessToken) {
        String key = "refresh:" + accessToken;
        return redisTemplate.opsForValue().get(key);
    }

    // Redis에서 refresh token 삭제 (예: 로그아웃 시)
    public void deleteRefreshToken(String userId) {
        String key = "refresh:" + userId;
        redisTemplate.delete(key);
    }
}