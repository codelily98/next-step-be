package com.next_step_be.next_step_be.config;

import com.next_step_be.next_step_be.jwt.JwtAuthenticationFilter;
import com.next_step_be.next_step_be.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays; // Arrays.asList를 위해 필요합니다.
import java.util.List; // List.of를 위해 필요합니다.

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtTokenProvider jwtTokenProvider;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // 프론트엔드의 모든 오리진을 포함합니다.
        configuration.setAllowedOrigins(List.of(
            "http://localhost:5173",          // 현재 프론트엔드 개발 서버의 오리진
            "http://127.0.0.1:5173",          // localhost 대신 127.0.0.1로 접근할 경우
            "http://localhost:3000",          // 혹시 모를 이전 설정 (React 기본 포트)
            "http://portfolio-nextstep.info", // 배포 환경 주소 (HTTP)
            "https://portfolio-nextstep.info" // 배포 환경 주소 (HTTPS)
        ));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        // ⭐ 이 부분을 수정합니다: "Refresh-Token" 헤더를 명시적으로 추가!
        // 기존 "X-Requested-With", "Accept"도 필요하다면 그대로 유지
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "Refresh-Token", "X-Requested-With", "Accept"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L); // Pre-flight 요청의 결과를 캐시할 시간 (초 단위)

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .cors(cors -> cors.configurationSource(corsConfigurationSource())) // 위에서 정의한 CORS 빈을 사용
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 세션 미사용
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll() // 로그인, 회원가입, 로그아웃 등 인증 관련 경로는 모두 허용
                .requestMatchers("/api/admin/**").hasRole("ADMIN") // ADMIN 역할이 필요한 경로
                .anyRequest().authenticated() // 나머지 모든 요청은 인증 필요
            )
            // JWT 인증 필터를 UsernamePasswordAuthenticationFilter 이전에 추가
            .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}