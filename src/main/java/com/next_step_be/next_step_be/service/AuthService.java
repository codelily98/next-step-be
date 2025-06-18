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
        	    .profileImageUrl("https://storage.googleapis.com/next-step-assets/uploads/default.png") // 기본값 (또는 default 이미지 경로)
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

        UserCacheDto userCache = new UserCacheDto(
        	    user.getUsername(),
        	    user.getNickname(),
        	    user.getRole(),
        	    user.getProfileImageUrl()
        	);

        String userKey = "user:" + user.getUsername();
        redisTemplate.opsForValue().set(userKey, toJson(userCache), 7, TimeUnit.DAYS);

        return new TokenResponse(accessToken, refreshToken);
    }

    @Transactional // Redis 작업 외에 DB 작업이 없다면 필수는 아님
    public TokenResponse refreshAccessToken(String oldRefreshToken) {
        // 1. 기존 리프레시 토큰 유효성 검사 (서명, 만료 여부)
        if (!jwtTokenProvider.validateToken(oldRefreshToken)) {
            throw new IllegalArgumentException("유효하지 않거나 만료된 Refresh Token입니다.");
        }

        String username = jwtTokenProvider.getUsernameFromToken(oldRefreshToken);
        String refreshKey = "refresh:" + username;
        String storedRefreshToken = redisTemplate.opsForValue().get(refreshKey);

        // 2. Redis에 저장된 토큰과 일치하는지 확인 (탈취/재사용 방지)
        if (storedRefreshToken == null || !storedRefreshToken.equals(oldRefreshToken)) {
            if (storedRefreshToken != null) { // 불일치하는 토큰이 Redis에 있다면 삭제하여 추가 재사용 방지
                redisTemplate.delete(refreshKey);
                log.warn("Refresh Token 불일치 감지. Redis 토큰 삭제: {}", username);
            } else {
                 log.warn("저장된 Refresh Token 없음. 재로그인 필요: {}", username);
            }
            throw new IllegalArgumentException("Refresh Token이 유효하지 않거나 이미 사용되었습니다. 다시 로그인해주세요.");
        }

        // 3. 기존 리프레시 토큰 무효화 (Redis에서 삭제)
        redisTemplate.delete(refreshKey); 
        log.info("기존 Refresh Token 무효화 완료: {}", username);

        // 4. 새로운 액세스 토큰 및 리프레시 토큰 발급
        Authentication authentication = jwtTokenProvider.getAuthentication(oldRefreshToken);
        String newAccessToken = jwtTokenProvider.generateToken(authentication, false);
        String newRefreshToken = jwtTokenProvider.generateToken(authentication, true);
        long newRefreshTokenExpirationMillis = jwtTokenProvider.getRefreshTokenExpiration();

        // 5. 새로운 리프레시 토큰 Redis 저장
        redisTemplate.opsForValue().set(refreshKey, newRefreshToken, newRefreshTokenExpirationMillis, TimeUnit.MILLISECONDS);
        log.info("새 AccessToken 및 RefreshToken 재발급 완료 - user: {}", username);

        // 6. 새로운 토큰들 반환
        return new TokenResponse(newAccessToken, newRefreshToken);
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
