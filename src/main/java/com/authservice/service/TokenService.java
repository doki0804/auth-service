package com.authservice.service;

import com.authservice.entity.User;
import com.authservice.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final JwtTokenProvider jwtTokenProvider;

    public String createAccessToken(User user) {
        return jwtTokenProvider.generateAccessToken(user);
    }

    public String createRefreshToken(User user) {
        return jwtTokenProvider.generateRefreshToken(user);
    }

    public boolean validateToken(String token) {
        return jwtTokenProvider.validateToken(token);
    }

    public String getUsername(String token) {
        return jwtTokenProvider.getUserIdFromToken(token);
    }

    public Date getExpiration(String token) {
        return jwtTokenProvider.getExpiration(token);
    }
}
