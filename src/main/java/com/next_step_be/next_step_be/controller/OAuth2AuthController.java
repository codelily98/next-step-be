//package com.next_step_be.next_step_be.controller;
//
//import jakarta.servlet.http.Cookie;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.RequiredArgsConstructor;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.data.redis.core.RedisTemplate;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.oauth2.core.user.OAuth2User;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.web.bind.annotation.*;
//import com.next_step_be.next_step_be.jwt.JwtTokenProvider;
//
//import java.io.IOException;
//import java.net.URLEncoder;
//import java.nio.charset.StandardCharsets;
//import java.util.List;
//import java.util.Map;
//import java.util.concurrent.TimeUnit;
//
//@RestController
//@RequestMapping("/api/auth/oauth2")
//@RequiredArgsConstructor
//public class OAuth2AuthController {
//
//    private final JwtTokenProvider jwtTokenProvider;
//    private final RedisTemplate<String, String> redisTemplate;
//
//    @Value("${frontend.oauth2-redirect-url}")
//    private String frontendOAuth2RedirectUrl;
//
//    @GetMapping("/success")
//    public void onSuccess(Authentication authentication, HttpServletResponse response) throws IOException {
//        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
//        String username = extractUsernameFromOAuth2(oAuth2User);
//
//        if (username == null || username.isBlank()) {
//            response.sendRedirect(frontendOAuth2RedirectUrl + "?error=" + URLEncoder.encode("Kakao user info (email/id) missing", StandardCharsets.UTF_8));
//            return;
//        }
//
//        UsernamePasswordAuthenticationToken authToken =
//            new UsernamePasswordAuthenticationToken(username, null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
//
//        String accessToken = jwtTokenProvider.generateToken(authToken, false);
//        String refreshToken = jwtTokenProvider.generateToken(authToken, true);
//
//        // Redis 저장
//        redisTemplate.opsForValue().set("refresh:" + username, refreshToken,
//                jwtTokenProvider.getRefreshTokenExpiration(), TimeUnit.MILLISECONDS);
//
//        // RefreshToken -> HttpOnly 쿠키 저장
//        Cookie cookie = new Cookie("refreshToken", refreshToken);
//        cookie.setHttpOnly(true);
//        cookie.setSecure(true); // HTTPS 환경에선 true 필수
//        cookie.setPath("/");
//        cookie.setMaxAge((int) (jwtTokenProvider.getRefreshTokenExpiration() / 1000));
//        response.addCookie(cookie);
//
//        // 프론트엔드로 accessToken 전달
//        String redirectUrl = frontendOAuth2RedirectUrl + "?accessToken=" + URLEncoder.encode(accessToken, StandardCharsets.UTF_8);
//        response.sendRedirect(redirectUrl);
//    }
//
//    @GetMapping("/failure")
//    public void onFailure(HttpServletResponse response) throws IOException {
//        response.sendRedirect(frontendOAuth2RedirectUrl + "?error=" + URLEncoder.encode("Social login failed", StandardCharsets.UTF_8));
//    }
//
//    /**
//     * OAuth2User 객체에서 username(email 또는 id)을 추출하는 헬퍼 메서드
//     */
//    private String extractUsernameFromOAuth2(OAuth2User oAuth2User) {
//        Map<String, Object> attributes = oAuth2User.getAttributes();
//
//        if (attributes.containsKey("kakao_account")) {
//        	Object kakaoAccountObj = attributes.get("kakao_account");
//        	if (kakaoAccountObj instanceof Map<?, ?> rawMap) {
//        	    Map<?, ?> genericMap = rawMap;
//        	    Object emailObj = genericMap.get("email");
//        	    if (emailObj instanceof String email) {
//        	        return email;
//        	    }
//        	}
//        }
//
//        Object id = oAuth2User.getAttribute("id");
//        return id != null ? String.valueOf(id) : null;
//    }
//}
