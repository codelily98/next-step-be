package com.next_step_be.next_step_be.controller;

import com.next_step_be.next_step_be.dto.LoginRequest;
import com.next_step_be.next_step_be.dto.RegisterRequest;
import com.next_step_be.next_step_be.dto.TokenResponse;
import com.next_step_be.next_step_be.service.AuthService;
import com.next_step_be.next_step_be.service.KakaoAuthService;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final KakaoAuthService kakaoAuthService;
    
    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterRequest request) {
        log.info("Attempting to register user: {}", request.getUsername());
        try {
            authService.register(request);
            log.info("User {} registered successfully.", request.getUsername());
            return ResponseEntity.status(HttpStatus.CREATED).body("User registered successfully");
        } catch (IllegalArgumentException e) {
            log.error("Failed to register user {}: {}", request.getUsername(), e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        } catch (Exception e) {
            log.error("An unexpected error occurred during registration for user {}: {}", request.getUsername(), e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Registration failed due to an internal server error.");
        }
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest request, HttpServletResponse response) {
        TokenResponse tokenResponse = authService.login(request);

        Cookie refreshTokenCookie = new Cookie("refreshToken", tokenResponse.getRefreshToken());
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(true);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge((int) (authService.getRefreshTokenExpiration() / 1000));
        response.addCookie(refreshTokenCookie);

        return ResponseEntity.ok(new TokenResponse(tokenResponse.getAccessToken(), null));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @RequestHeader("Authorization") String accessTokenHeader,
            @CookieValue(value = "refreshToken", required = false) String refreshToken,
            HttpServletResponse response) {

        String accessToken = null;
        if (accessTokenHeader != null && accessTokenHeader.startsWith("Bearer ")) {
            accessToken = accessTokenHeader.substring(7);
        }

        if (accessToken == null || refreshToken == null) {
            return ResponseEntity.badRequest().body("AccessToken 또는 RefreshToken이 없습니다.");
        }

        boolean loggedOut = authService.logout(accessToken, refreshToken);

        Cookie cookie = new Cookie("refreshToken", null);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);

        return loggedOut ?
                ResponseEntity.ok("Logout successful.") :
                ResponseEntity.badRequest().body("Logout failed or token not found.");
    }
    
    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(
            @CookieValue(name = "refreshToken", required = false) String refreshToken) {

        if (refreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh Token is missing.");
        }

        try {
            String newAccessToken = authService.refreshAccessToken(refreshToken);
            return ResponseEntity.ok(new TokenResponse(newAccessToken, null));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Token refresh failed.");
        }
    }

    @PostMapping("/kakao/logout")
    public ResponseEntity<String> kakaoLogout(@RequestHeader("Authorization") String authorizationHeader) {
        // "Bearer " 접두사를 제거하고 액세스 토큰만 추출
        String accessToken = authorizationHeader.replace("Bearer ", "");
        String result = kakaoAuthService.kakaoLogout(accessToken);
        return ResponseEntity.ok(result);
    }

    @PostMapping("/kakao/unlink")
    public ResponseEntity<String> kakaoUnlink(@RequestHeader("Authorization") String authorizationHeader) {
        String accessToken = authorizationHeader.replace("Bearer ", "");
        String result = kakaoAuthService.kakaoUnlink(accessToken);
        return ResponseEntity.ok(result);
    }

}
