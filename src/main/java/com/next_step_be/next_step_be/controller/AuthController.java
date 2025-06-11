package com.next_step_be.next_step_be.controller;

import com.next_step_be.next_step_be.dto.LoginRequest;
import com.next_step_be.next_step_be.dto.RegisterRequest;
import com.next_step_be.next_step_be.dto.TokenResponse;
import com.next_step_be.next_step_be.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j // Lombok 로깅
@RestController // RESTful 웹 서비스 컨트롤러
@RequestMapping("/api/auth") // 기본 URL 경로 설정
@RequiredArgsConstructor // final 필드를 위한 생성자 자동 생성
public class AuthController {

    private final AuthService authService; // 인증 비즈니스 로직 서비스

    // 회원가입 API
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

    // 로그인 API
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest request) {
        log.info("Attempting to log in user: {}", request.getUsername());
        try {
            TokenResponse tokenResponse = authService.login(request);
            log.info("User {} logged in successfully, tokens issued.", request.getUsername());
            return ResponseEntity.ok(tokenResponse);
        } catch (Exception e) {
            log.error("Login failed for user {}: {}", request.getUsername(), e.getMessage(), e);
            // 인증 실패 시 (비밀번호 불일치, 사용자 없음 등) BadCredentialsException 발생
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build(); // 401 Unauthorized
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String accessTokenHeader,
                                   @RequestHeader("Refresh-Token") String refreshToken) {
        // "Bearer " 접두사 제거
        String accessToken = null;
        if (accessTokenHeader != null && accessTokenHeader.startsWith("Bearer ")) {
            accessToken = accessTokenHeader.substring(7);
        } else {
            return ResponseEntity.badRequest().body("Access Token is missing or malformed.");
        }

        boolean loggedOut = authService.logout(accessToken, refreshToken);
        if (loggedOut) {
            return ResponseEntity.ok("Logout successful.");
        } else {
            return ResponseEntity.badRequest().body("Logout failed or token not found.");
        }
    }
    
    // (선택 사항) 테스트용 API (인증 필요)
    // @GetMapping("/test")
    // @PreAuthorize("hasRole('USER')") // USER 권한 필요
    // public ResponseEntity<String> testEndpoint() {
    //     return ResponseEntity.ok("This is a protected endpoint! You are authenticated.");
    // }
    //
    // @GetMapping("/admin/test")
    // @PreAuthorize("hasRole('ADMIN')") // ADMIN 권한 필요
    // public ResponseEntity<String> adminTestEndpoint() {
    //     return ResponseEntity.ok("This is an ADMIN-only endpoint!");
    // }
}