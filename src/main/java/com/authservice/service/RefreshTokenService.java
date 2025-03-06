package com.authservice.service;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class RefreshTokenService {

    private final RedisTemplate<String, String> redisTemplate;
    private final long refreshTokenValiditySeconds = 7 * 24 * 60 * 60;

    public RefreshTokenService(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void saveRefreshToken(String userId, String refreshToken) {
        String key = "refresh:" + userId;
        redisTemplate.opsForValue().set(key, refreshToken, refreshTokenValiditySeconds, TimeUnit.SECONDS);
    }

    // Redis에서 refresh token 조회
    public String getRefreshToken(String userId) {
        String key = "refresh:" + userId;
        return redisTemplate.opsForValue().get(key);
    }

    // Redis에서 refresh token 삭제 (예: 로그아웃 시)
    public void deleteRefreshToken(String userId) {
        String key = "refresh:" + userId;
        redisTemplate.delete(key);
    }
}