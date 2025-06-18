package com.next_step_be.next_step_be.dto;

import lombok.Data;

@Data
public class RegisterRequest {
    private String username;
    private String password;
}
