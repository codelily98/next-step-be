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
    private final ObjectMapper objectMapper;

    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtTokenProvider jwtTokenProvider,
            AuthenticationManager authenticationManager,
            @Qualifier("redisTemplate") RedisTemplate<String, String> redisTemplate,
            ObjectMapper objectMapper
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
        this.authenticationManager = authenticationManager;
        this.redisTemplate = redisTemplate;
        this.objectMapper = objectMapper;
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
                .profileImageUrl("https://storage.googleapis.com/next-step-assets/uploads/default.png")
                .build();

        return userRepository.save(user);
    }

    @Transactional
    public TokenResponse login(LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(), request.getPassword()
                )
        );

        String accessToken = jwtTokenProvider.generateToken(authentication, false);
        String refreshToken = jwtTokenProvider.generateToken(authentication, true);

        String username = authentication.getName();
        long refreshTTL = jwtTokenProvider.getRefreshTokenExpiration();

        // Redis 저장
        redisTemplate.opsForValue().set("refresh:" + username, refreshToken, refreshTTL, TimeUnit.MILLISECONDS);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("사용자 정보가 존재하지 않습니다."));
        saveUserCache(user);

        return new TokenResponse(accessToken, refreshToken);
    }

    @Transactional
    public TokenResponse refreshAccessToken(String oldRefreshToken) {
        if (!jwtTokenProvider.validateToken(oldRefreshToken)) {
            throw new IllegalArgumentException("유효하지 않거나 만료된 Refresh Token입니다.");
        }

        String username = jwtTokenProvider.getUsernameFromToken(oldRefreshToken);
        String redisKey = "refresh:" + username;
        String storedToken = redisTemplate.opsForValue().get(redisKey);

        if (storedToken == null || !storedToken.equals(oldRefreshToken)) {
            redisTemplate.delete(redisKey);
            log.warn("🔐 Refresh Token 불일치 또는 존재하지 않음: {}", username);
            throw new IllegalArgumentException("Refresh Token이 유효하지 않거나 만료되었습니다. 다시 로그인해주세요.");
        }

        // 기존 토큰 무효화
        redisTemplate.delete(redisKey);

        Authentication authentication = jwtTokenProvider.getAuthentication(oldRefreshToken);
        String newAccessToken = jwtTokenProvider.generateToken(authentication, false);
        String newRefreshToken = jwtTokenProvider.generateToken(authentication, true);
        long newTTL = jwtTokenProvider.getRefreshTokenExpiration();

        redisTemplate.opsForValue().set(redisKey, newRefreshToken, newTTL, TimeUnit.MILLISECONDS);
        log.info("♻️ RefreshToken 재발급 완료: {}", username);

        return new TokenResponse(newAccessToken, newRefreshToken);
    }

    @Transactional
    public boolean logout(String accessToken, String refreshToken) {
        String username = jwtTokenProvider.getUsernameFromToken(accessToken);

        // RefreshToken 삭제
        String refreshKey = "refresh:" + username;
        boolean existed = Boolean.TRUE.equals(redisTemplate.hasKey(refreshKey));
        if (existed) {
            redisTemplate.delete(refreshKey);
        }

        // AccessToken 블랙리스트 등록
        Long expiration = jwtTokenProvider.getExpiration(accessToken);
        if (expiration != null && expiration > 0) {
            redisTemplate.opsForValue().set("blacklist:" + accessToken, "logout", expiration, TimeUnit.MILLISECONDS);
        }

        // 유저 캐시 제거
        redisTemplate.delete("user:" + username);
        log.info("🚪 로그아웃 처리 완료: {}", username);
        return existed;
    }

    public long getRefreshTokenExpiration() {
        return jwtTokenProvider.getRefreshTokenExpiration();
    }

    private void saveUserCache(User user) {
        try {
            UserCacheDto dto = new UserCacheDto(
                    user.getUsername(),
                    user.getNickname(),
                    user.getRole(),
                    user.getProfileImageUrl()
            );
            String json = objectMapper.writeValueAsString(dto);
            redisTemplate.opsForValue().set("user:" + user.getUsername(), json, 7, TimeUnit.DAYS);
        } catch (Exception e) {
            log.error("❗ 유저 캐시 저장 실패: {}", e.getMessage());
        }
    }
}
