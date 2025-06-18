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

        String registrationId = request.getClientRegistration().getRegistrationId();
        String userNameAttributeName = request.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();

        Map<String, Object> attributes = oAuth2User.getAttributes();

        if (!"kakao".equals(registrationId)) {
            throw new OAuth2AuthenticationException("지원되지 않는 OAuth2 제공자입니다.");
        }

        Object kakaoAccountObj = attributes.get("kakao_account");
        if (!(kakaoAccountObj instanceof Map<?, ?> rawMap)) {
            throw new OAuth2AuthenticationException("kakao_account 정보가 없습니다.");
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> kakaoAccount = (Map<String, Object>) rawMap;

        String email = (String) kakaoAccount.get("email");
        if (email == null || email.isEmpty()) {
            throw new OAuth2AuthenticationException("카카오 계정에서 이메일을 가져올 수 없습니다.");
        }

        String nickname = "KakaoUser";
        Object profileObj = kakaoAccount.get("profile");
        if (profileObj instanceof Map<?, ?> profileMapRaw) {
            @SuppressWarnings("unchecked")
            Map<String, Object> profileMap = (Map<String, Object>) profileMapRaw;
            Object nicknameObj = profileMap.get("nickname");
            if (nicknameObj instanceof String str) {
                nickname = str;
            }
        }

        final String safeEmail = email;
        final String safeNickname = nickname;

        User user = userRepository.findByUsername(safeEmail).orElseGet(() ->
            userRepository.save(User.builder()
                .username(safeEmail)
                .nickname(safeNickname)
                .password(passwordEncoder.encode("KAKAO_" + safeEmail))
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
