package com.next_step_be.next_step_be.service;

import com.next_step_be.next_step_be.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service // 스프링 빈으로 등록
@Slf4j
@RequiredArgsConstructor // final 필드를 위한 생성자 자동 생성
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository; // 사용자 정보 접근 리포지토리

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    	log.info("🔍 사용자 로드 요청: {}", username);
        // 사용자 이름으로 User 엔티티를 찾아 반환
        return userRepository.findByUsername(username)
        		.orElseThrow(() -> {
                    log.warn("❌ 사용자 없음: {}", username);
                    return new UsernameNotFoundException("User not found with username: " + username);
                });
    }
}