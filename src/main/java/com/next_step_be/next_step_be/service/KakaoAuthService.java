package com.next_step_be.next_step_be.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Slf4j
@Service
public class KakaoAuthService {

    private final RestTemplate restTemplate;

    @Value("${custom.kakao.admin-key}")
    private String adminKey;

    public KakaoAuthService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String kakaoLogout(String accessToken) {
        String logoutApiUrl = "https://kapi.kakao.com/v1/user/logout";

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<String> entity = new HttpEntity<>(null, headers);

        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    logoutApiUrl,
                    HttpMethod.POST,
                    entity,
                    String.class
            );
            return response.getBody();
        } catch (Exception e) {
            log.error("카카오 로그아웃 실패: {}", e.getMessage(), e);
            return "Logout failed: " + e.getMessage();
        }
    }

    public String kakaoUnlink(String accessToken) {
        String unlinkApiUrl = "https://kapi.kakao.com/v1/user/unlink";

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<String> entity = new HttpEntity<>(null, headers);

        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    unlinkApiUrl,
                    HttpMethod.POST,
                    entity,
                    String.class
            );
            return response.getBody();
        } catch (Exception e) {
            log.error("카카오 회원 탈퇴 실패: {}", e.getMessage(), e);
            return "Unlink failed: " + e.getMessage();
        }
    }

    public String kakaoUnlinkWithAdminKey(String userId) {
        String unlinkApiUrl = "https://kapi.kakao.com/v1/user/unlink";

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "KakaoAK " + adminKey); // ✅ 필드 adminKey 사용
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        String requestBody = "target_id_type=user_id&target_id=" + userId;

        HttpEntity<String> entity = new HttpEntity<>(requestBody, headers);

        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    unlinkApiUrl,
                    HttpMethod.POST,
                    entity,
                    String.class
            );
            return response.getBody();
        } catch (Exception e) {
            log.error("어드민 키를 사용한 연결 끊기 실패: {}", e.getMessage(), e);
            return "Unlink with Admin Key failed: " + e.getMessage();
        }
    }
}
