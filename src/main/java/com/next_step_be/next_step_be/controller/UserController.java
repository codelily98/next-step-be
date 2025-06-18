package com.next_step_be.next_step_be.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.next_step_be.next_step_be.dto.UserCacheDto;
import com.next_step_be.next_step_be.service.UserService;

import lombok.RequiredArgsConstructor;

import java.util.Map;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import com.next_step_be.next_step_be.domain.User;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

    private final RedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final UserService userService;

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(@AuthenticationPrincipal User principal) {
        String username = principal.getUsername();
        String userKey = "user:" + username;

        try {
            String cachedUser = redisTemplate.opsForValue().get(userKey);
            if (cachedUser != null) {
                UserCacheDto userDto = objectMapper.readValue(cachedUser, UserCacheDto.class);
                return ResponseEntity.ok(userDto);
            } else {
                return ResponseEntity.status(404).body("사용자 캐시가 존재하지 않습니다.");
            }
        } catch (Exception e) {
            return ResponseEntity.status(500).body("사용자 정보를 가져오는 중 오류 발생");
        }
    }
    
    @PostMapping("/check-nickname")
    public ResponseEntity<?> checkNickname(
            @RequestBody Map<String, String> body,
            @AuthenticationPrincipal User user
    ) {
        String nickname = body.get("nickname");

        if (nickname == null || nickname.trim().isEmpty()) {
            return ResponseEntity.badRequest().body("닉네임을 입력해주세요.");
        }

        // 본인의 기존 닉네임이면 중복 아님
        if (nickname.trim().equals(user.getNickname())) {
            return ResponseEntity.ok("본인의 기존 닉네임입니다.");
        }

        // 다른 사용자의 닉네임과 중복되는 경우
        boolean exists = userService.nicknameExists(nickname.trim());

        return exists
                ? ResponseEntity.status(HttpStatus.CONFLICT).body("중복된 닉네임입니다.")
                : ResponseEntity.ok("사용 가능한 닉네임입니다.");
    }


    @PutMapping
    public ResponseEntity<String> updateProfile(
            @RequestPart("nickname") String nickname,
            @RequestPart(value = "profileImage", required = false) MultipartFile profileImage,
            @AuthenticationPrincipal User user) {

        userService.updateProfile(user.getUsername(), nickname, profileImage);
        return ResponseEntity.ok("프로필이 성공적으로 수정되었습니다.");
    }
}
