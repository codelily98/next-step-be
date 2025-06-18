package com.next_step_be.next_step_be.dto;

import com.next_step_be.next_step_be.domain.Role;
import com.next_step_be.next_step_be.domain.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserCacheDto implements Serializable {
    private static final long serialVersionUID = 1L;

    private String username;
    private String nickname;
    private Role role;
    private String profileImageUrl;

    // ✅ User → UserCacheDto 변환용 팩토리 메서드
    public static UserCacheDto from(User user) {
        return UserCacheDto.builder()
                .username(user.getUsername())
                .nickname(user.getNickname())
                .role(user.getRole())
                .profileImageUrl(user.getProfileImageUrl())
                .build();
    }
}
