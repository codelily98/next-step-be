package com.next_step_be.next_step_be.dto;

import lombok.Data; // Lombok @Data 어노테이션 사용

@Data // @Getter, @Setter, @EqualsAndHashCode, @ToString 등을 포함
public class LoginRequest {
    private String username;
    private String password;
}