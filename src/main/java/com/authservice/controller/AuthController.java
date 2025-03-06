package com.authservice.controller;

import com.authservice.dto.request.LoginRequest;
import com.authservice.dto.request.RefreshTokenRequest;
import com.authservice.dto.response.AccessTokenResponse;
import com.authservice.dto.response.AuthResponse;
import com.authservice.entity.User;
import com.authservice.service.RedisService;
import com.authservice.service.RefreshTokenService;
import com.authservice.service.TokenService;
import com.authservice.service.UserService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;
import java.util.Optional;

@RestController
@AllArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final TokenService tokenService;
    private final RefreshTokenService refreshTokenService;
    private final RedisService redisService;
    private final PasswordEncoder passwordEncoder;

    // 로그인: 사용자 인증 후 Access Token과 Refresh Token 생성 및 Redis 저장
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        Optional<User> userOpt = userService.findByUsername(loginRequest.getUserId());
        if (userOpt.isPresent() && passwordMatches(loginRequest.getPassword(), userOpt.get().getPassword())) {
            User user = userOpt.get();
            String accessToken = tokenService.generateAccessToken(user);
            String refreshToken = tokenService.generateRefreshToken(user);
            // Redis에 refresh token 저장
            refreshTokenService.saveRefreshToken(user.getUserId(), refreshToken);
            return ResponseEntity.ok(new AuthResponse(accessToken, refreshToken));
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
    }

    // 토큰 재발급: 클라이언트가 제공한 refresh token과 Redis에 저장된 값을 비교하여 새로운 Access Token 발급
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest request) {
        // 클라이언트가 요청한 username에 해당하는 refresh token을 Redis에서 조회
        String storedToken = refreshTokenService.getRefreshToken(request.getUserId());
        if (storedToken != null
                && storedToken.equals(request.getRefreshToken())
                && tokenService.validateToken(request.getRefreshToken())) {
            Optional<User> userOpt = userService.findByUsername(request.getUserId());
            if (userOpt.isPresent()) {
                String newAccessToken = tokenService.generateAccessToken(userOpt.get());
                return ResponseEntity.ok(new AccessTokenResponse(newAccessToken));
            }
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh token is invalid or expired");
    }

    // 로그아웃: Access Token은 블랙리스트 처리, Refresh Token은 Redis에서 삭제
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        String token = resolveToken(request);
        if (token != null) {
            Date expiration = getExpiration(token);
            long remainingMillis = expiration.getTime() - System.currentTimeMillis();
            redisService.blacklistToken(token, remainingMillis);
            // 예: 현재 로그인한 사용자의 refresh token 삭제 (추가 로직 필요)
            String username = tokenService.getUsernameFromToken(token);
            refreshTokenService.deleteRefreshToken(username);
        }
        return ResponseEntity.ok("Logged out successfully");
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    // JWT 토큰의 만료일 정보를 추출 (예외 발생 시 1970년 반환)
    private Date getExpiration(String token) {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey("yourSecretKey")
                    .parseClaimsJws(token)
                    .getBody();
            return claims.getExpiration();
        } catch (Exception ex) {
            return new Date(0);
        }
    }

    // 비밀번호 검증: rawPassword와 암호화된 encodedPassword 비교
    private boolean passwordMatches(String rawPassword, String encodedPassword) {
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }
}