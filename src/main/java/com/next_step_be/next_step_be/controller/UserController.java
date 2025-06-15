package com.next_step_be.next_step_be.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.next_step_be.next_step_be.dto.UserCacheDto;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

    private final RedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper();

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
}
