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
    @Value("${frontend.oauth2-redirect-url}") // 새로운 속성 이름 사용을 권장합니다.
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
                                // 실패 시에도 동일한 frontendOAuth2RedirectUrl 사용
                                response.sendRedirect(frontendOAuth2RedirectUrl + "?error=" + URLEncoder.encode("Kakao user info (email/id) missing", StandardCharsets.UTF_8));
                                return;
                            }
                        }

                        String role = "ROLE_USER";

                        UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(username, null, List.of(new SimpleGrantedAuthority(role)));

                        String accessToken = jwtTokenProvider.generateToken(authToken, false);
                        String refreshToken = jwtTokenProvider.generateToken(authToken, true);

                        if (username != null && !username.isEmpty()) {
                            redisTemplate.opsForValue().set("refresh:" + username, refreshToken,
                                    jwtTokenProvider.getRefreshTokenExpiration(), TimeUnit.MILLISECONDS);
                        } else {
                            // 실패 시에도 동일한 frontendOAuth2RedirectUrl 사용
                            response.sendRedirect(frontendOAuth2RedirectUrl + "?error=" + URLEncoder.encode("Failed to save refresh token (username invalid)", StandardCharsets.UTF_8));
                            return;
                        }

                        Cookie cookie = new Cookie("refreshToken", refreshToken);
                        cookie.setHttpOnly(true);
                        cookie.setSecure(true);
                        cookie.setPath("/");
                        cookie.setMaxAge((int) (jwtTokenProvider.getRefreshTokenExpiration() / 1000));
                        response.addCookie(cookie);

                        // 성공 시에도 동일한 frontendOAuth2RedirectUrl 사용
                        String redirectUrl = frontendOAuth2RedirectUrl + "?accessToken=" + URLEncoder.encode(accessToken, StandardCharsets.UTF_8);
                        response.sendRedirect(redirectUrl);

                        cookieAuthorizationRequestRepository.removeAuthorizationRequestCookies(request, response);

                    } catch (IOException e) {
                        System.err.println("Error in OAuth2 successHandler: " + e.getMessage());
                        response.sendRedirect(frontendOAuth2RedirectUrl + "?error=" + URLEncoder.encode("Internal server error during login", StandardCharsets.UTF_8));
                    }
                })
                .failureHandler((request, response, exception) -> {
                    try {
                        String errorMessage = exception.getMessage() != null ? exception.getMessage() : "Authentication failed";
                        // ✅ 실패 시 frontendOAuth2RedirectUrl로 리다이렉트
                        response.sendRedirect(frontendOAuth2RedirectUrl + "?error=" + URLEncoder.encode(errorMessage, StandardCharsets.UTF_8));
                    } catch (IOException e) {
                        System.err.println("Error in OAuth2 failureHandler: " + e.getMessage());
                    }
                })
            );

        http.addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}