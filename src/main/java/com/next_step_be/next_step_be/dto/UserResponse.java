package com.next_step_be.next_step_be.dto;

import com.next_step_be.next_step_be.domain.Role;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class UserResponse {
    private final String username;
    private final String nickname;
    private final String profileImageUrl;
    private final Role role;

    public static UserResponse from(UserCacheDto dto) {
        return UserResponse.builder()
                .username(dto.getUsername())
                .nickname(dto.getNickname() != null ? dto.getNickname() : "사용자")
                .profileImageUrl(dto.getProfileImageUrl() != null
                        ? dto.getProfileImageUrl()
                        : "https://storage.googleapis.com/next-step-assets/uploads/default.png")
                .role(dto.getRole())
                .build();
    }
}
