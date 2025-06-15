package com.next_step_be.next_step_be.service;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class KakaoAuthService {

    private final RestTemplate restTemplate;

    public KakaoAuthService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    /**
     * 카카오 로그아웃 (액세스 토큰 만료)
     * @param accessToken 사용자의 액세스 토큰
     * @return 로그아웃 결과 (성공 시 사용자 고유 ID 포함)
     */
    public String kakaoLogout(String accessToken) {
        String logoutApiUrl = "https://kapi.kakao.com/v1/user/logout";

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken); // 액세스 토큰을 Bearer 타입으로 전송
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED); // POST 요청 바디 타입

        HttpEntity<String> entity = new HttpEntity<>(headers); // 바디는 필요 없음 (빈 문자열 또는 null)

        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    logoutApiUrl,
                    HttpMethod.POST,
                    entity,
                    String.class
            );
            return response.getBody(); // 응답 결과 (예: {"id":123456789})
        } catch (Exception e) {
            // 오류 처리 로직
            e.printStackTrace();
            return "Logout failed: " + e.getMessage();
        }
    }

    /**
     * 카카오 연결 끊기 (회원 탈퇴)
     * @param accessToken 사용자의 액세스 토큰
     * @return 연결 끊기 결과 (성공 시 사용자 고유 ID 포함)
     */
    public String kakaoUnlink(String accessToken) {
        String unlinkApiUrl = "https://kapi.kakao.com/v1/user/unlink";

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<String> entity = new HttpEntity<>(headers);

        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    unlinkApiUrl,
                    HttpMethod.POST,
                    entity,
                    String.class
            );
            return response.getBody(); // 응답 결과 (예: {"id":123456789})
        } catch (Exception e) {
            e.printStackTrace();
            return "Unlink failed: " + e.getMessage();
        }
    }

    // 어드민 키를 사용한 로그아웃/연결 끊기는 보안상 서버 내에서만 호출되어야 합니다.
    // 예시: 어드민 키를 사용하여 특정 사용자의 연결 끊기
    public String kakaoUnlinkWithAdminKey(Long userId) {
        String unlinkApiUrl = "https://kapi.kakao.com/v1/user/unlink";
        String adminKey = "YOUR_KAKAO_APP_ADMIN_KEY"; // 실제 어드민 키로 대체하세요!

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "KakaoAK " + adminKey);
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        // 요청 바디에 사용자 ID 포함
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
            e.printStackTrace();
            return "Unlink with Admin Key failed: " + e.getMessage();
        }
    }
}