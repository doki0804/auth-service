package com.authservice.service;

import com.authservice.dto.request.LoginRequest;
import com.authservice.dto.request.RefreshTokenRequest;
import com.authservice.dto.response.AccessTokenResponse;
import com.authservice.dto.response.AuthResponse;
import com.authservice.entity.User;
import com.authservice.exception.UnauthorizedException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserService userService;
    private final TokenService tokenService;
    private final RefreshTokenService refreshTokenService;
    private final RedisService redisService;
    private final PasswordEncoder passwordEncoder;

    // 로그인 처리: 사용자 인증 후 토큰 생성 및 Redis에 refresh token 저장
    public AuthResponse login(LoginRequest loginRequest) {
        Optional<User> userOpt = userService.findByUsername(loginRequest.getUserId());
        if (userOpt.isPresent() &&
                passwordEncoder.matches(loginRequest.getPassword(), userOpt.get().getPassword())) {
            User user = userOpt.get();
            String accessToken = tokenService.createAccessToken(user);
            String refreshToken = tokenService.createRefreshToken(user);
            refreshTokenService.saveRefreshToken(user.getUserId(), refreshToken);
            return new AuthResponse(accessToken, refreshToken);
        } else {
            throw new UnauthorizedException("Invalid credentials");
        }
    }

    // 토큰 재발급: 클라이언트가 보낸 refresh token과 Redis 저장값 비교 후 새 Access Token 발급
    public AccessTokenResponse refreshToken(RefreshTokenRequest request) {
        String storedToken = refreshTokenService.getRefreshToken(request.getUserId());
        if (storedToken != null &&
                storedToken.equals(request.getRefreshToken()) &&
                tokenService.validateToken(request.getRefreshToken())) {
            User user = userService.findByUsername(request.getUserId())
                    .orElseThrow(() -> new UnauthorizedException("User not found"));
            String newAccessToken = tokenService.createAccessToken(user);
            return new AccessTokenResponse(newAccessToken);
        } else {
            throw new UnauthorizedException("Refresh token is invalid or expired");
        }
    }

    // 로그아웃 처리: Access Token은 블랙리스트 등록, 해당 사용자의 refresh token 삭제
    public void logout(HttpServletRequest request) {
        String token = resolveToken(request);
        if (token != null) {
            Date expiration = tokenService.getExpiration(token);
            long remainingMillis = expiration.getTime() - System.currentTimeMillis();
            redisService.blacklistToken(token, remainingMillis);
            String username = tokenService.getUsername(token);
            refreshTokenService.deleteRefreshToken(username);
        }
    }

    // Authorization 헤더에서 JWT 토큰 추출
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
