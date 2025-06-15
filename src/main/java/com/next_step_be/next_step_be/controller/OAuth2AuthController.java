package com.next_step_be.next_step_be.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value; // @Value 어노테이션 추가
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import com.next_step_be.next_step_be.jwt.JwtTokenProvider;
import java.io.IOException; // IOException 추가
import java.net.URLEncoder; // URLEncoder 추가
import java.nio.charset.StandardCharsets; // StandardCharsets 추가
import java.util.List;
import java.util.Map; // 카카오 계정 정보 파싱을 위해 Map 추가
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/api/auth/oauth2")
@RequiredArgsConstructor
public class OAuth2AuthController {

    private final JwtTokenProvider jwtTokenProvider;
    private final RedisTemplate<String, String> redisTemplate;

    // application.yml에서 프론트엔드 URL을 주입받습니다.
    @Value("${frontend.oauth2-redirect-url}") // ✅ 이 부분으로 변경
    private String frontendOAuth2RedirectUrl;

    @GetMapping("/success")
    // 반환 타입을 ResponseEntity<?> -> void 로 변경하고 IOException을 던지도록 합니다.
    public void onSuccess(Authentication authentication, HttpServletResponse response) throws IOException {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        String username = null;
        // 카카오 OAuth2User 객체의 실제 구조를 확인하여 email을 추출합니다.
        // 일반적으로 "kakao_account" -> "email" 경로에 있습니다.
        // 디버깅 시 System.out.println(oAuth2User.getAttributes()); 를 찍어 정확한 구조를 확인하세요.
        Map<String, Object> attributes = oAuth2User.getAttributes();
        if (attributes != null && attributes.containsKey("kakao_account")) {
            Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
            if (kakaoAccount != null && kakaoAccount.containsKey("email")) {
                username = (String) kakaoAccount.get("email");
            }
        }
        
        // 이메일이 없는 경우 카카오 고유 ID를 username으로 사용
        if (username == null || username.isEmpty()) {
            Object id = oAuth2User.getAttribute("id"); // 카카오 고유 ID는 보통 Long 타입으로 제공됩니다.
            if (id != null) {
                username = String.valueOf(id);
            } else {
                response.sendRedirect(frontendOAuth2RedirectUrl + "?error=" + URLEncoder.encode("Kakao user info (email/id) missing", StandardCharsets.UTF_8));
                return;
            }
        }

        String role = "ROLE_USER"; // 기본 USER 권한 부여

        UsernamePasswordAuthenticationToken authToken =
            new UsernamePasswordAuthenticationToken(username, null, List.of(new SimpleGrantedAuthority(role)));

        String accessToken = jwtTokenProvider.generateToken(authToken, false);
        String refreshToken = jwtTokenProvider.generateToken(authToken, true);

        // RefreshToken Redis 저장 (username 유효성 검사 추가)
        if (username != null && !username.isEmpty()) {
            redisTemplate.opsForValue().set("refresh:" + username, refreshToken,
                    jwtTokenProvider.getRefreshTokenExpiration(), TimeUnit.MILLISECONDS);
        } else {
            response.sendRedirect(frontendOAuth2RedirectUrl + "?error=" + URLEncoder.encode("Failed to save refresh token (username invalid)", StandardCharsets.UTF_8));
            return;
        }

        // RefreshToken 쿠키 저장
        Cookie cookie = new Cookie("refreshToken", refreshToken);
        cookie.setHttpOnly(true);
        // HTTPS 운영 환경에서는 true로 설정해야 합니다. (로컬 HTTP 개발 시에는 false일 수 있음)
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge((int) (jwtTokenProvider.getRefreshTokenExpiration() / 1000));
        response.addCookie(cookie);

        // **프론트엔드로 리다이렉트**
        // AccessToken을 쿼리 파라미터로 전달하여 프론트엔드가 받도록 합니다.
        String redirectUrl = frontendOAuth2RedirectUrl + "?accessToken=" + URLEncoder.encode(accessToken, StandardCharsets.UTF_8);
        response.sendRedirect(redirectUrl); // 브라우저를 프론트엔드 URL로 리다이렉트!
    }

    @GetMapping("/failure")
    public void onFailure(HttpServletResponse response) throws IOException {
        // 로그인 실패 시 프론트엔드의 실패 페이지로 리다이렉트
        response.sendRedirect(frontendOAuth2RedirectUrl + "?error=" + URLEncoder.encode("Social login failed", StandardCharsets.UTF_8));
    }
}