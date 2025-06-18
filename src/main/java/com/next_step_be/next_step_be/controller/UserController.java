package com.next_step_be.next_step_be.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.next_step_be.next_step_be.domain.User;
import com.next_step_be.next_step_be.dto.UpdateProfileRequest;
import com.next_step_be.next_step_be.dto.UserCacheDto;
import com.next_step_be.next_step_be.dto.UserResponse;
import com.next_step_be.next_step_be.service.UserService;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

    private final RedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final UserService userService;

    // ✅ 로그인 사용자 정보 반환 (Redis 캐시 → DB fallback → null-safe DTO 반환)
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(@AuthenticationPrincipal User principal) {
        String username = principal.getUsername();
        String userKey = "user:" + username;

        try {
            String cachedUser = redisTemplate.opsForValue().get(userKey);
            if (cachedUser != null) {
                UserCacheDto userDto = objectMapper.readValue(cachedUser, UserCacheDto.class);
                return ResponseEntity.ok(UserResponse.from(userDto));
            } else {
                // 캐시에 없을 경우 DB에서 사용자 정보 조회
                User dbUser = userService.getUserByUsername(username);
                if (dbUser == null) {
                    return ResponseEntity.status(404).body("사용자 정보를 찾을 수 없습니다.");
                }

                UserCacheDto fallbackUser = UserCacheDto.builder()
                        .username(dbUser.getUsername())
                        .nickname(dbUser.getNickname())
                        .role(dbUser.getRole())
                        .profileImageUrl(dbUser.getProfileImageUrl())
                        .build();

                // Redis 캐싱 추가
                String json = objectMapper.writeValueAsString(fallbackUser);
                redisTemplate.opsForValue().set(userKey, json);

                return ResponseEntity.ok(UserResponse.from(fallbackUser));
            }

        } catch (Exception e) {
            return ResponseEntity.status(500).body("사용자 정보를 가져오는 중 오류 발생");
        }
    }

    // ✅ 닉네임 중복 검사
    @PostMapping("/check-nickname")
    public ResponseEntity<?> checkNickname(
            @RequestBody Map<String, String> body,
            @AuthenticationPrincipal User user
    ) {
        String nickname = body.get("nickname");

        if (nickname == null || nickname.trim().isEmpty()) {
            return ResponseEntity.badRequest().body("닉네임을 입력해주세요.");
        }

        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("인증되지 않은 사용자입니다.");
        }

        String currentNickname = user.getNickname();
        if (currentNickname != null && currentNickname.equals(nickname.trim())) {
            return ResponseEntity.ok("본인의 기존 닉네임입니다.");
        }

        boolean exists = userService.nicknameExists(nickname.trim());
        return exists
                ? ResponseEntity.status(HttpStatus.CONFLICT).body("중복된 닉네임입니다.")
                : ResponseEntity.ok("사용 가능한 닉네임입니다.");
    }

    // ✅ 사용자 프로필 업데이트 (닉네임 + 프로필 이미지)
    @PutMapping
    public ResponseEntity<String> updateProfile(
            @ModelAttribute UpdateProfileRequest request,
            @AuthenticationPrincipal User user) {

        userService.updateProfile(user.getUsername(), request);
        return ResponseEntity.ok("프로필이 성공적으로 수정되었습니다.");
    }
}
