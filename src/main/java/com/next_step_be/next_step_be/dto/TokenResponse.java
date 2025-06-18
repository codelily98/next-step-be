package com.next_step_be.next_step_be.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class TokenResponse {
    private String accessToken;
    private String refreshToken;
    
    // 에러 메시지 반환용 생성자
    public TokenResponse(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }
}