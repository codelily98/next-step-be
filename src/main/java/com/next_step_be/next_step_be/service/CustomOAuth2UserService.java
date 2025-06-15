package com.next_step_be.next_step_be.service;

import com.next_step_be.next_step_be.domain.Role;
import com.next_step_be.next_step_be.domain.User;
import com.next_step_be.next_step_be.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest request) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = new DefaultOAuth2UserService().loadUser(request);

        String registrationId = request.getClientRegistration().getRegistrationId(); // "kakao"
        String userNameAttributeName = request.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();

        Map<String, Object> attributes = oAuth2User.getAttributes();

        // 카카오 사용자 정보 추출
        Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
        String email = (String) kakaoAccount.get("email");
        String nickname = (String) ((Map<String, Object>) kakaoAccount.get("profile")).get("nickname");

        // 사용자 등록 또는 업데이트
        User user = userRepository.findByUsername(email).orElseGet(() ->
            userRepository.save(User.builder()
                .username(email)
                .password(passwordEncoder.encode("KAKAO_" + email)) // 외부 로그인 식별용
                .role(Role.USER)
                .build())
        );

        return new DefaultOAuth2User(
            Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")),
            attributes,
            userNameAttributeName
        );
    }
}
