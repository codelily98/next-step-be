package com.next_step_be.next_step_be.service;

import com.next_step_be.next_step_be.domain.Role;
import com.next_step_be.next_step_be.domain.User;
import com.next_step_be.next_step_be.dto.LoginRequest;
import com.next_step_be.next_step_be.dto.RegisterRequest;
import com.next_step_be.next_step_be.dto.TokenResponse;
import com.next_step_be.next_step_be.jwt.JwtTokenProvider;
import com.next_step_be.next_step_be.repository.UserRepository;
//import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate; // Redis 연동을 위해 추가
import java.util.concurrent.TimeUnit; // Redis TTL 설정을 위해 추가

@Slf4j // Lombok 로깅
@Service // 스프링 빈으로 등록
//@RequiredArgsConstructor // final 필드를 위한 생성자 자동 생성
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final RedisTemplate<String, String> redisTemplate; // RedisTemplate 주입

    // 수동으로 생성자 정의 및 @Qualifier 적용
    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtTokenProvider jwtTokenProvider,
            AuthenticationManagerBuilder authenticationManagerBuilder,
            @Qualifier("redisTemplate") RedisTemplate<String, String> redisTemplate) { // <-- 생성자 파라미터에 @Qualifier
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
        this.redisTemplate = redisTemplate;
    }
    
    // 회원가입 처리
    @Transactional // 트랜잭션 관리
    public User register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException("이미 존재하는 사용자 이름입니다.");
        }

        // 비밀번호 암호화
        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER) // 기본 권한을 USER로 설정
                .build();

        return userRepository.save(user); // DB에 사용자 저장
    }

    // 로그인 처리 및 JWT 토큰 발급
    @Transactional // 트랜잭션 관리
    public TokenResponse login(LoginRequest request) {
        // 1. Username + Password 기반으로 Authentication 객체 생성
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword());

        // 2. 실제 검증 (사용자 비밀번호 체크)
        // authenticate 메서드가 CustomUserDetailsService의 loadUserByUsername을 호출하여 DB에서 사용자 정보를 가져오고,
        // PasswordEncoder를 사용하여 비밀번호를 비교합니다.
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        // 3. 인증 정보를 기반으로 Access Token과 Refresh Token 생성
        String accessToken = jwtTokenProvider.generateToken(authentication, false);
        String refreshToken = jwtTokenProvider.generateToken(authentication, true);

        // 4. Refresh Token을 Redis에 저장 (key: username, value: refreshToken, expiration: Refresh Token 만료 시간)
        // Refresh Token의 만료 시간을 application.yml에서 가져와 Redis TTL로 설정
        long refreshTokenExpirationMillis = jwtTokenProvider.getRefreshTokenExpiration(); // JWT 프로바이더에서 만료 시간 가져오는 메서드 추가 필요
        redisTemplate.opsForValue().set(authentication.getName(), refreshToken, refreshTokenExpirationMillis, TimeUnit.MILLISECONDS);

        log.info("User {} logged in successfully. Access Token: {}, Refresh Token stored in Redis.", request.getUsername(), accessToken);

        return new TokenResponse(accessToken, refreshToken);
    }
    
    /**
     * 로그아웃 처리 메서드
     * @param accessToken 로그아웃하려는 사용자의 Access Token
     * @param refreshToken 로그아웃하려는 사용자의 Refresh Token
     * @return 로그아웃 성공 여부 (true/false)
     */
    public boolean logout(String accessToken, String refreshToken) {
        // 1. Access Token에서 사용자명(principal) 추출 (필요하다면)
        String username = jwtTokenProvider.getUsernameFromToken(accessToken);

        // 2. Redis에서 Refresh Token 삭제
        // Refresh Token의 키가 사용자명이라면
        if (redisTemplate.hasKey(username)) {
            redisTemplate.delete(username);
        } else {
            // Redis에 Refresh Token이 이미 없거나 유효하지 않은 경우 (로그아웃 처리 불필요)
            // 혹은 Access Token에서 추출한 사용자명이 잘못된 경우
            return false;
        }

        // 3. (선택 사항) Access Token 블랙리스트 처리:
        // Access Token의 잔여 유효 시간을 가져와서 Redis에 블랙리스트로 저장합니다.
        // 이렇게 하면 Access Token의 유효 기간이 남았더라도 더 이상 사용하지 못하게 합니다.
        Long expiration = jwtTokenProvider.getExpiration(accessToken);
        if (expiration != null && expiration > 0) {
            redisTemplate.opsForValue().set(accessToken, "logout", expiration, TimeUnit.MILLISECONDS);
            // Access Token을 키로 하여 'logout'이라는 값을 저장, Access Token의 남은 유효 시간 동안 유효
        }

        return true;
    }
}