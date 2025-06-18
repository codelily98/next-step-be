package com.next_step_be.next_step_be.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.next_step_be.next_step_be.domain.User;
import com.next_step_be.next_step_be.dto.UserCacheDto;
import com.next_step_be.next_step_be.dto.UserResponse;
import com.next_step_be.next_step_be.jwt.JwtTokenProvider;
import com.next_step_be.next_step_be.service.UserService;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

    private final RedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final UserService userService;
    private final JwtTokenProvider jwtTokenProvider;

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

                String json = objectMapper.writeValueAsString(fallbackUser);
                redisTemplate.opsForValue().set(userKey, json);

                return ResponseEntity.ok(UserResponse.from(fallbackUser));
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

    @PutMapping
    public ResponseEntity<?> updateProfile(
            @RequestParam String nickname,
            @RequestParam(required = false) MultipartFile profileImage, // 파일을 받는 부분
            @AuthenticationPrincipal User user) {

        if (user == null || user.getUsername() == null || user.getRole() == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("인증 정보가 유효하지 않습니다.");
        }

        try {
            // 프로필 업데이트
            userService.updateProfile(user.getUsername(), nickname, profileImage);

            // 토큰 재발급
            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), null,
                            List.of(new SimpleGrantedAuthority(user.getRole().name())));

            String accessToken = jwtTokenProvider.generateToken(authToken, false);
            String refreshToken = jwtTokenProvider.generateToken(authToken, true);

            if (accessToken == null || refreshToken == null) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("토큰 생성에 실패했습니다.");
            }

            // Redis에 RefreshToken 저장
            redisTemplate.opsForValue().set(
                    "refresh:" + user.getUsername(),
                    refreshToken,
                    jwtTokenProvider.getRefreshTokenExpiration(),
                    TimeUnit.MILLISECONDS
            );

            // 사용자 정보 최신화
            User updatedUser = userService.getUserByUsername(user.getUsername());
            UserCacheDto updatedCache = UserCacheDto.builder()
                    .username(updatedUser.getUsername())
                    .nickname(updatedUser.getNickname())
                    .role(updatedUser.getRole())
                    .profileImageUrl(updatedUser.getProfileImageUrl())
                    .build();

            // Redis 캐시 갱신
            try {
                String json = objectMapper.writeValueAsString(updatedCache);
                redisTemplate.opsForValue().set("user:" + updatedUser.getUsername(), json);
            } catch (Exception e) {
                // 예외 발생 시 로깅 남기기
                e.printStackTrace();
            }

            // 응답 구성
            Map<String, Object> response = new HashMap<>();
            response.put("message", "프로필이 성공적으로 수정되었습니다.");
            response.put("accessToken", accessToken);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("프로필 수정 중 오류가 발생했습니다: " + e.getMessage());
        }
    }
}
