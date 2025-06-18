package com.next_step_be.next_step_be.dto;

import com.next_step_be.next_step_be.domain.Role;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserCacheDto {
	private String username;
    private String nickname;
    private Role role;
    private String profileImageUrl;
}