package com.next_step_be.next_step_be.controller;

import com.next_step_be.next_step_be.service.AdminAuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
public class AdminAuthController {

    private final AdminAuthService adminAuthService;

    @DeleteMapping("/logout/{username}")
    @PreAuthorize("hasRole('ADMIN')") // 🔐 관리자 권한만 허용
    public ResponseEntity<String> forceLogout(@PathVariable String username) {
        boolean success = adminAuthService.forceLogout(username);
        return success
                ? ResponseEntity.ok("강제 로그아웃 성공")
                : ResponseEntity.badRequest().body("사용자 토큰이 존재하지 않습니다.");
    }
}
