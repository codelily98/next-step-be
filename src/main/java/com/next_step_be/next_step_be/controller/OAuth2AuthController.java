package com.next_step_be.next_step_be.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import com.next_step_be.next_step_be.dto.TokenResponse;
import com.next_step_be.next_step_be.jwt.JwtTokenProvider;
import java.util.List;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/api/auth/oauth2")
@RequiredArgsConstructor
public class OAuth2AuthController {

    private final JwtTokenProvider jwtTokenProvider;
    private final RedisTemplate<String, String> redisTemplate;

    @GetMapping("/success")
    public ResponseEntity<?> onSuccess(Authentication authentication, HttpServletResponse response) {
        // Principal로부터 사용자 정보 추출
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String username = oAuth2User.getAttribute("email"); // 카카오는 kakao_account.email로 다를 수 있음

        // 권한 부여 (기본 USER)
        String role = "ROLE_USER";

        // JWT 생성
        UsernamePasswordAuthenticationToken authToken =
            new UsernamePasswordAuthenticationToken(username, null, List.of(new SimpleGrantedAuthority(role)));

        String accessToken = jwtTokenProvider.generateToken(authToken, false);
        String refreshToken = jwtTokenProvider.generateToken(authToken, true);

        // RefreshToken Redis 저장
        redisTemplate.opsForValue().set("refresh:" + username, refreshToken,
                jwtTokenProvider.getRefreshTokenExpiration(), TimeUnit.MILLISECONDS);

        // RefreshToken 쿠키 저장
        Cookie cookie = new Cookie("refreshToken", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge((int) (jwtTokenProvider.getRefreshTokenExpiration() / 1000));
        response.addCookie(cookie);

        // accessToken만 프론트에 전달
        return ResponseEntity.ok(new TokenResponse(accessToken, null));
    }

    @GetMapping("/failure")
    public ResponseEntity<?> onFailure() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("소셜 로그인 실패");
    }
}
