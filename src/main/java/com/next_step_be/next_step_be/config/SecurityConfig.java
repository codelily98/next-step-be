package com.next_step_be.next_step_be.config;

// 추가 및 수정된 Import 문들
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import jakarta.servlet.http.Cookie;
import java.io.IOException; // successHandler 람다에서 IOException을 던질 수 있으므로 추가
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.next_step_be.next_step_be.jwt.JwtAuthenticationFilter;
import com.next_step_be.next_step_be.jwt.JwtTokenProvider;
import com.next_step_be.next_step_be.repository.CookieAuthorizationRequestRepository; // 패키지 경로 확인!
import com.next_step_be.next_step_be.service.CustomUserDetailsService;

import lombok.RequiredArgsConstructor;

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
public class SecurityConfig {

    private final JwtTokenProvider jwtTokenProvider;
    private final CustomUserDetailsService customUserDetailsService;
    private final CookieAuthorizationRequestRepository cookieAuthorizationRequestRepository;
    private final RedisTemplate<String, String> redisTemplate; // ✅ RedisTemplate 주입 추가

    // ✅ 프론트엔드 URL 주입 추가
    @Value("${frontend.oauth2-success-url}")
    private String frontendSuccessUrl;

    @Value("${frontend.oauth2-failure-url}")
    private String frontendFailureUrl;

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
        // ✅ 수정된 부분: setAllowedOriginPatterns 대신 setAllowedOrigins를 사용하여 정확한 출처를 지정
        configuration.setAllowedOrigins(List.of("https://portfolio-nextstep.info", "http://localhost:3000")); // 로컬 개발용도 추가
        // 개발 완료 후 "http://localhost:3000"은 제거하는 것이 좋습니다.

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
                .requestMatchers("/api/auth/**", "/login/oauth2/**", "/oauth2/**").permitAll() // OAuth2 관련 경로 허용
                .requestMatchers(HttpMethod.POST, "/api/register").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .authorizationEndpoint(authorization -> authorization
                    .baseUri("/oauth2/authorization") // OAuth2 로그인 시작 URL
                    .authorizationRequestRepository(cookieAuthorizationRequestRepository) // ✅ 커스텀 리포지토리 설정
                )
                .redirectionEndpoint(redirection -> redirection
                    .baseUri("/login/oauth2/code/*") // 카카오에서 리다이렉트될 URL 패턴
                )
                .successHandler((request, response, authentication) -> {
                    // ✅ 기존 OAuth2AuthController.onSuccess의 로직을 여기에 직접 구현합니다.
                    // 이 람다 내부에서 IOException이 발생할 수 있으므로, 람다의 선언부에는 `throws IOException`이 필요합니다.
                    // (함수형 인터페이스 정의에 따라 자동으로 처리되거나, 람다 내부에서 try-catch 블록으로 감싸야 함)
                    // Spring Security의 successHandler는 ServletOutputStream을 사용하므로, IOException을 던져도 괜찮습니다.
                    try {
                        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

                        String username = null;
                        Map<String, Object> attributes = oAuth2User.getAttributes();
                        if (attributes != null && attributes.containsKey("kakao_account")) {
                            Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
                            if (kakaoAccount != null && kakaoAccount.containsKey("email")) {
                                username = (String) kakaoAccount.get("email");
                            }
                        }
                        
                        if (username == null || username.isEmpty()) {
                            Object id = oAuth2User.getAttribute("id");
                            if (id != null) {
                                username = String.valueOf(id);
                            } else {
                                response.sendRedirect(frontendFailureUrl + "?error=" + URLEncoder.encode("Kakao user info (email/id) missing", StandardCharsets.UTF_8));
                                return;
                            }
                        }

                        String role = "ROLE_USER"; // 기본 USER 권한 부여

                        UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(username, null, List.of(new SimpleGrantedAuthority(role)));

                        String accessToken = jwtTokenProvider.generateToken(authToken, false);
                        String refreshToken = jwtTokenProvider.generateToken(authToken, true);

                        // RefreshToken Redis 저장 (username 유효성 검사 추가)
                        if (username != null && !username.isEmpty()) {
                            redisTemplate.opsForValue().set("refresh:" + username, refreshToken,
                                    jwtTokenProvider.getRefreshTokenExpiration(), TimeUnit.MILLISECONDS);
                        } else {
                            response.sendRedirect(frontendFailureUrl + "?error=" + URLEncoder.encode("Failed to save refresh token (username invalid)", StandardCharsets.UTF_8));
                            return;
                        }

                        // RefreshToken 쿠키 저장
                        Cookie cookie = new Cookie("refreshToken", refreshToken);
                        cookie.setHttpOnly(true);
                        // HTTPS 운영 환경에서는 true로 설정해야 합니다. (로컬 HTTP 개발 시에는 false일 수 있음)
                        cookie.setSecure(true); // 배포 환경에선 반드시 true로 설정!
                        cookie.setPath("/");
                        cookie.setMaxAge((int) (jwtTokenProvider.getRefreshTokenExpiration() / 1000));
                        response.addCookie(cookie);

                        // 프론트엔드로 리다이렉트
                        // AccessToken을 쿼리 파라미터로 전달하여 프론트엔드가 받도록 합니다.
                        String redirectUrl = frontendSuccessUrl + "?accessToken=" + URLEncoder.encode(accessToken, StandardCharsets.UTF_8);
                        response.sendRedirect(redirectUrl);

                        // 쿠키에 저장된 AuthorizationRequest 정보 삭제
                        cookieAuthorizationRequestRepository.removeAuthorizationRequestCookies(request, response);

                    } catch (IOException e) {
                        // 예외 발생 시 에러 로깅 또는 추가 처리
                        System.err.println("Error in OAuth2 successHandler: " + e.getMessage());
                        // 필요하다면 실패 페이지로 리다이렉트
                        response.sendRedirect(frontendFailureUrl + "?error=" + URLEncoder.encode("Internal server error during login", StandardCharsets.UTF_8));
                    }
                })
                .failureHandler((request, response, exception) -> {
                    // ✅ 기존 OAuth2AuthController.onFailure의 로직을 여기에 구현
                    try {
                        String errorMessage = exception.getMessage() != null ? exception.getMessage() : "Authentication failed";
                        response.sendRedirect(frontendFailureUrl + "?error=" + URLEncoder.encode(errorMessage, StandardCharsets.UTF_8));
                    } catch (IOException e) {
                        System.err.println("Error in OAuth2 failureHandler: " + e.getMessage());
                    }
                })
            );

        http.addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}