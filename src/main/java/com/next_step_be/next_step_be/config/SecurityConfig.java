package com.next_step_be.next_step_be.config;

// 추가 및 수정된 Import 문들
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest; // HttpServletRequest 임포트 추가
import jakarta.servlet.http.HttpServletResponse; // HttpServletResponse 임포트 추가
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.next_step_be.next_step_be.jwt.JwtAuthenticationFilter;
import com.next_step_be.next_step_be.jwt.JwtTokenProvider;
import com.next_step_be.next_step_be.repository.CookieAuthorizationRequestRepository;
import com.next_step_be.next_step_be.service.CustomUserDetailsService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j; // 로깅을 위해 Slf4j 임포트 추가

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Slf4j // Slf4j 어노테이션 추가
public class SecurityConfig {

    private final JwtTokenProvider jwtTokenProvider;
    private final CustomUserDetailsService customUserDetailsService;
    private final CookieAuthorizationRequestRepository cookieAuthorizationRequestRepository;
    private final RedisTemplate<String, String> redisTemplate;

    @Value("${frontend.oauth2-redirect-url}")
    private String frontendOAuth2RedirectUrl;

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(customUserDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("https://portfolio-nextstep.info", "http://localhost:5173"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "Refresh-Token", "X-Requested-With", "Accept"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/api/auth/**", "/login/oauth2/**", "/oauth2/**").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/register").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .authorizationEndpoint(authorization -> authorization
                    .baseUri("/oauth2/authorization")
                    .authorizationRequestRepository(cookieAuthorizationRequestRepository)
                )
                .redirectionEndpoint(redirection -> redirection
                    .baseUri("/login/oauth2/code/*")
                )
                .successHandler((request, response, authentication) -> {
                    try {
                        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

                        // extractUsernameFromOAuth2 헬퍼 메서드 사용
                        String username = extractUsernameFromOAuth2(oAuth2User);

                        if (username == null || username.isEmpty()) {
                            log.warn("카카오 사용자 정보 (이메일/ID) 누락: {}", oAuth2User.getAttributes());
                            response.sendRedirect(frontendOAuth2RedirectUrl + "?error=" + URLEncoder.encode("Kakao user info (email/id) missing", StandardCharsets.UTF_8));
                            return;
                        }

                        String role = "ROLE_USER"; // 필요에 따라 역할 부여 로직 추가

                        UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(username, null, List.of(new SimpleGrantedAuthority(role)));

                        String accessToken = jwtTokenProvider.generateToken(authToken, false);
                        String refreshToken = jwtTokenProvider.generateToken(authToken, true);

                        if (username != null && !username.isEmpty()) {
                            redisTemplate.opsForValue().set("refresh:" + username, refreshToken,
                                    jwtTokenProvider.getRefreshTokenExpiration(), TimeUnit.MILLISECONDS);
                            log.info("카카오 로그인 성공 및 토큰 발급: {}", username);
                        } else {
                            log.error("토큰 저장을 위한 사용자 이름이 유효하지 않음: {}", username);
                            response.sendRedirect(frontendOAuth2RedirectUrl + "?error=" + URLEncoder.encode("Failed to save refresh token (username invalid)", StandardCharsets.UTF_8));
                            return;
                        }

                        Cookie cookie = new Cookie("refreshToken", refreshToken);
                        cookie.setHttpOnly(true);
                        cookie.setSecure(true);
                        cookie.setPath("/");
                        cookie.setMaxAge((int) (jwtTokenProvider.getRefreshTokenExpiration() / 1000));
                        response.addCookie(cookie);

                        String redirectUrl = frontendOAuth2RedirectUrl + "?accessToken=" + URLEncoder.encode(accessToken, StandardCharsets.UTF_8);
                        response.sendRedirect(redirectUrl);

                        cookieAuthorizationRequestRepository.removeAuthorizationRequestCookies(request, response);

                    } catch (IOException e) {
                        log.error("OAuth2 successHandler 처리 중 IO 예외 발생: {}", e.getMessage(), e);
                        response.sendRedirect(frontendOAuth2RedirectUrl + "?error=" + URLEncoder.encode("Internal server error during login", StandardCharsets.UTF_8));
                    } catch (Exception e) { // 기타 예외 처리 추가
                        log.error("OAuth2 successHandler 처리 중 알 수 없는 예외 발생: {}", e.getMessage(), e);
                        response.sendRedirect(frontendOAuth2RedirectUrl + "?error=" + URLEncoder.encode("Unexpected error during login", StandardCharsets.UTF_8));
                    }
                })
                .failureHandler((request, response, exception) -> {
                    try {
                        String errorMessage = exception.getMessage() != null ? exception.getMessage() : "Authentication failed";
                        log.error("OAuth2 로그인 실패: {}", errorMessage, exception);
                        response.sendRedirect(frontendOAuth2RedirectUrl + "?error=" + URLEncoder.encode(errorMessage, StandardCharsets.UTF_8));
                    } catch (IOException e) {
                        log.error("OAuth2 failureHandler 처리 중 IO 예외 발생: {}", e.getMessage(), e);
                    }
                })
            );

        http.addFilterBefore(
            new JwtAuthenticationFilter(jwtTokenProvider, redisTemplate),
            UsernamePasswordAuthenticationFilter.class
        );

        return http.build();
    }

    /**
     * OAuth2User 객체에서 username(email 또는 id)을 추출하는 헬퍼 메서드
     * 이 메서드는 SecurityConfig 클래스 내부에서만 사용됩니다.
     */
    private String extractUsernameFromOAuth2(OAuth2User oAuth2User) {
        Map<String, Object> attributes = oAuth2User.getAttributes();

        // 카카오 계정 정보에서 이메일 추출 시도
        if (attributes != null && attributes.containsKey("kakao_account")) {
            Object kakaoAccountObj = attributes.get("kakao_account");
            if (kakaoAccountObj instanceof Map<?, ?> rawMap) {
                Map<?, ?> genericMap = rawMap;
                Object emailObj = genericMap.get("email");
                if (emailObj instanceof String email) {
                    return email;
                }
            }
        }

        // 이메일이 없을 경우, id (숫자)를 사용자 이름으로 사용
        Object id = oAuth2User.getAttribute("id");
        return id != null ? String.valueOf(id) : null;
    }
}