package com.next_step_be.next_step_be.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.next_step_be.next_step_be.domain.Role;
import com.next_step_be.next_step_be.domain.User;
import com.next_step_be.next_step_be.dto.LoginRequest;
import com.next_step_be.next_step_be.dto.RegisterRequest;
import com.next_step_be.next_step_be.dto.TokenResponse;
import com.next_step_be.next_step_be.dto.UserCacheDto;
import com.next_step_be.next_step_be.jwt.JwtTokenProvider;
import com.next_step_be.next_step_be.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.concurrent.TimeUnit;

@Slf4j
@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;
    private final RedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper(); // JSON 변환기

    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtTokenProvider jwtTokenProvider,
            AuthenticationManager authenticationManager,
            @Qualifier("redisTemplate") RedisTemplate<String, String> redisTemplate) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
        this.authenticationManager = authenticationManager;
        this.redisTemplate = redisTemplate;
    }

    @Transactional
    public User register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException("이미 존재하는 사용자 이름입니다.");
        }

        long userCount = userRepository.count();
        String generatedNickname = "user" + (userCount + 1);

        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .nickname(generatedNickname)
                .build();

        return userRepository.save(user);
    }

    @Transactional
    public TokenResponse login(LoginRequest request) {
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword());

        Authentication authentication = authenticationManager.authenticate(authenticationToken);

        String accessToken = jwtTokenProvider.generateToken(authentication, false);
        String refreshToken = jwtTokenProvider.generateToken(authentication, true);
        long refreshTokenExpirationMillis = jwtTokenProvider.getRefreshTokenExpiration();

        // 🔹 RefreshToken Redis 저장
        String refreshKey = "refresh:" + authentication.getName();
        redisTemplate.opsForValue().set(refreshKey, refreshToken, refreshTokenExpirationMillis, TimeUnit.MILLISECONDS);

        // 🔹 사용자 정보 Redis 캐싱 (7일 고정 TTL)
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("사용자 없음"));

        UserCacheDto userCache = new UserCacheDto(user.getUsername(), user.getNickname(), user.getRole());

        String userKey = "user:" + user.getUsername();
        redisTemplate.opsForValue().set(userKey, toJson(userCache), 7, TimeUnit.DAYS);

        return new TokenResponse(accessToken, refreshToken);
    }

    public String refreshAccessToken(String refreshToken) {
        if (!jwtTokenProvider.validateToken(refreshToken)) {
            throw new IllegalArgumentException("유효하지 않은 Refresh Token입니다.");
        }

        String username = jwtTokenProvider.getUsernameFromToken(refreshToken);
        String key = "refresh:" + username;
        String storedToken = redisTemplate.opsForValue().get(key);

        if (storedToken == null || !storedToken.equals(refreshToken)) {
            throw new IllegalArgumentException("Refresh Token이 만료되었거나 저장되지 않았습니다.");
        }

        // 🎯 RefreshToken TTL 연장만 수행 (user 캐시는 그대로 둠)
        long ttl = jwtTokenProvider.getRefreshTokenExpiration();
        redisTemplate.opsForValue().set(key, storedToken, ttl, TimeUnit.MILLISECONDS);

        Authentication authentication = jwtTokenProvider.getAuthentication(refreshToken);
        return jwtTokenProvider.generateToken(authentication, false);
    }

    public boolean logout(String accessToken, String refreshToken) {
        String username = jwtTokenProvider.getUsernameFromToken(accessToken);

        // 🔧 Key 이름 일치화
        String refreshKey = "refresh:" + username;
        if (redisTemplate.hasKey(refreshKey)) {
            redisTemplate.delete(refreshKey);
        } else {
            return false;
        }

        Long expiration = jwtTokenProvider.getExpiration(accessToken);
        if (expiration != null && expiration > 0) {
            redisTemplate.opsForValue().set(accessToken, "logout", expiration, TimeUnit.MILLISECONDS);
        }

        // 사용자 캐시 삭제 (선택 사항)
        redisTemplate.delete("user:" + username);

        return true;
    }

    public long getRefreshTokenExpiration() {
        return jwtTokenProvider.getRefreshTokenExpiration();
    }

    // JSON 변환 헬퍼
    private String toJson(Object obj) {
        try {
            return objectMapper.writeValueAsString(obj);
        } catch (Exception e) {
            throw new RuntimeException("JSON 직렬화 실패", e);
        }
    }
}
