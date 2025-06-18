package com.next_step_be.next_step_be.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final RedisTemplate<String, String> redisTemplate;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String accessToken = resolveToken(request);
        String requestURI = request.getRequestURI();

        try {
            if (accessToken != null && jwtTokenProvider.validateToken(accessToken)) {
                Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);
                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.debug("✅ 유효한 AccessToken으로 인증 완료: {}", authentication.getName());

            } else if (accessToken != null && jwtTokenProvider.isExpiredToken(accessToken)) {
                String refreshToken = getRefreshTokenFromCookies(request);

                if (refreshToken != null && jwtTokenProvider.validateToken(refreshToken)) {
                    String username = jwtTokenProvider.getUsernameFromToken(refreshToken);
                    String redisRefresh = redisTemplate.opsForValue().get("refresh:" + username);

                    if (refreshToken.equals(redisRefresh)) {
                        Authentication authentication = jwtTokenProvider.getAuthentication(refreshToken);
                        SecurityContextHolder.getContext().setAuthentication(authentication);

                        String newAccessToken = jwtTokenProvider.generateToken(authentication, false);
                        String newRefreshToken = jwtTokenProvider.generateToken(authentication, true);

                        redisTemplate.opsForValue().set("refresh:" + username, newRefreshToken,
                                jwtTokenProvider.getRefreshTokenExpiration(), TimeUnit.MILLISECONDS);

                        response.setHeader("Authorization", "Bearer " + newAccessToken);

                        Cookie newCookie = new Cookie("refreshToken", newRefreshToken);
                        newCookie.setHttpOnly(true);
                        newCookie.setSecure(true);
                        newCookie.setPath("/");
                        newCookie.setMaxAge((int) (jwtTokenProvider.getRefreshTokenExpiration() / 1000));
                        response.addCookie(newCookie);

                        log.info("♻️ AccessToken + RefreshToken 재발급 완료 - user: {}", username);
                    } else {
                        log.warn("❌ Redis에 저장된 RefreshToken과 일치하지 않음");
                    }
                } else {
                    log.warn("❌ RefreshToken이 유효하지 않음");
                }

            } else {
                log.debug("❌ 유효한 JWT 토큰이 없음 - uri: {}", requestURI);
            }

        } catch (Exception e) {
            log.error("❗ JWT 필터 처리 중 예외 - uri: {}, message: {}", requestURI, e.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        return (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer "))
                ? bearerToken.substring(7)
                : null;
    }

    private String getRefreshTokenFromCookies(HttpServletRequest request) {
        if (request.getCookies() == null) return null;
        for (Cookie cookie : request.getCookies()) {
            if ("refreshToken".equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }
}
