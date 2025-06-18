package com.next_step_be.next_step_be.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.next_step_be.next_step_be.domain.User;
import com.next_step_be.next_step_be.dto.UpdateProfileRequest;
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
            @ModelAttribute UpdateProfileRequest request,
            @AuthenticationPrincipal User user) {

        userService.updateProfile(user.getUsername(), request);

        // 사용자 정보 갱신
        User updatedUser = userService.getUserByUsername(user.getUsername());

        // 토큰 재발급
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(
                        updatedUser.getUsername(),
                        null,
                        List.of(new SimpleGrantedAuthority(updatedUser.getRole().name()))
                );

        String accessToken = jwtTokenProvider.generateToken(authToken, false);
        String refreshToken = jwtTokenProvider.generateToken(authToken, true);

        // Redis refreshToken 저장
        redisTemplate.opsForValue().set(
                "refresh:" + updatedUser.getUsername(),
                refreshToken,
                jwtTokenProvider.getRefreshTokenExpiration(),
                TimeUnit.MILLISECONDS
        );

        // 캐시 갱신
        UserCacheDto updatedCache = UserCacheDto.builder()
                .username(updatedUser.getUsername())
                .nickname(updatedUser.getNickname())
                .role(updatedUser.getRole())
                .profileImageUrl(updatedUser.getProfileImageUrl())
                .build();

        try {
            String json = objectMapper.writeValueAsString(updatedCache);
            redisTemplate.opsForValue().set("user:" + updatedUser.getUsername(), json);
        } catch (Exception ignored) {}

        // FE에 사용자 정보도 같이 전달 (💡 중요)
        return ResponseEntity.ok(Map.of(
                "message", "프로필이 성공적으로 수정되었습니다.",
                "accessToken", accessToken,
                "nickname", updatedUser.getNickname(),
                "profileImageUrl", updatedUser.getProfileImageUrl()
        ));
    }
}
