package com.next_step_be.next_step_be.repository;

import com.nimbusds.oauth2.sdk.util.StringUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Optional;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;
import jakarta.servlet.http.Cookie; // jakarta.servlet.http.Cookie 임포트 확인

@Component
public class CookieAuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {
    public static final String OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME = "oauth2_auth_request";
    public static final String REDIRECT_URI_PARAM_COOKIE_NAME = "redirect_uri";
    private static final int COOKIE_EXPIRE_SECONDS = 180; // 3분

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        // 쿠키에서 인증 요청 정보 로드
        Cookie cookie = WebUtils.getCookie(request, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME);
        // ⭐ 이 부분이 중요합니다. Cookie 객체를 Optional.ofNullable로 감싸서 map 메서드를 사용할 수 있게 합니다.
        return Optional.ofNullable(cookie)
                .map(c -> CookieUtils.deserialize(c, OAuth2AuthorizationRequest.class))
                .orElse(null);
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request, HttpServletResponse response) {
        if (authorizationRequest == null) {
            // 인증 요청이 null이면 관련 쿠키 삭제
            removeAuthorizationRequestCookies(request, response);
            return;
        }

        // 인증 요청 정보를 쿠키에 저장
        CookieUtils.addCookie(response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME,
                CookieUtils.serialize(authorizationRequest), COOKIE_EXPIRE_SECONDS);

        // redirect_uri 파라미터도 쿠키에 저장 (사용자가 로그인 후 돌아갈 원래 페이지)
        String redirectUriAfterLogin = request.getParameter(REDIRECT_URI_PARAM_COOKIE_NAME);
        if (StringUtils.isNotBlank(redirectUriAfterLogin)) {
            CookieUtils.addCookie(response, REDIRECT_URI_PARAM_COOKIE_NAME,
                    redirectUriAfterLogin, COOKIE_EXPIRE_SECONDS);
        }
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
        // 인증 요청 정보 로드 후, 관련 쿠키 삭제
        return this.loadAuthorizationRequest(request); // Spring Security 5.3부터 이 메서드만 호출되면 쿠키는 자동으로 삭제되지 않음
                                                        // 따라서 saveAuthorizationRequest에서 null 처리 시 쿠키 삭제 로직을 사용하거나,
                                                        // successHandler 또는 failureHandler에서 명시적으로 삭제해야 함.
    }

    // 인증 요청 관련 쿠키를 모두 삭제하는 헬퍼 메서드 (인증 성공/실패 후 호출)
    public void removeAuthorizationRequestCookies(HttpServletRequest request, HttpServletResponse response) {
        CookieUtils.deleteCookie(request, response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME);
        CookieUtils.deleteCookie(request, response, REDIRECT_URI_PARAM_COOKIE_NAME);
    }
}

// 쿠키를 다루기 위한 유틸리티 클래스 (내부 클래스로 포함하거나 별도 파일로 분리 가능)
// 여기서는 편의상 내부 클래스로 포함시켰습니다. 실제 프로젝트에서는 별도 유틸 파일로 분리하는 것이 좋습니다.
class CookieUtils {

    public static void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(maxAge);
        response.addCookie(cookie);
    }

    public static void deleteCookie(HttpServletRequest request, HttpServletResponse response, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null && cookies.length > 0) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(name)) {
                    cookie.setValue("");
                    cookie.setPath("/");
                    cookie.setMaxAge(0);
                    response.addCookie(cookie);
                }
            }
        }
    }

    public static String serialize(Object object) {
        // 객체를 base64 인코딩된 문자열로 직렬화
        return java.util.Base64.getUrlEncoder()
                .encodeToString(org.springframework.util.SerializationUtils.serialize(object));
    }

    public static <T> T deserialize(Cookie cookie, Class<T> cls) {
        // base64 인코딩된 문자열을 객체로 역직렬화
        return cls.cast(org.springframework.util.SerializationUtils.deserialize(
                java.util.Base64.getUrlDecoder().decode(cookie.getValue())));
    }
}