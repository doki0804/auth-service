package com.authservice.service;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class RedisService {

    private final RedisTemplate<String, String> redisTemplate;

    public RedisService(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    // 토큰 블랙리스트 등록 (만료 시간 설정)
    public void blacklistToken(String token, long expirationMillis) {
        redisTemplate.opsForValue().set("blacklist:" + token, "true", expirationMillis, TimeUnit.MILLISECONDS);
    }

    // 블랙리스트에 등록된 토큰인지 확인
    public boolean isTokenBlacklisted(String token) {
        return Boolean.TRUE.equals(redisTemplate.hasKey("blacklist:" + token));
    }
}
