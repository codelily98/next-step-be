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
            // 🔒 블랙리스트 확인
            if (accessToken != null && redisTemplate.hasKey("blacklist:" + accessToken)) {
                log.warn("🚫 블랙리스트 처리된 AccessToken 요청 차단 - uri: {}", requestURI);
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "로그아웃된 토큰입니다.");
                return;
            }

            if (accessToken != null && jwtTokenProvider.validateToken(accessToken)) {
                Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);
                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.debug("✅ 유효한 AccessToken으로 인증 완료: {}", authentication.getName());

            } else if (accessToken != null && jwtTokenProvider.isExpiredToken(accessToken)) {
                // 🔄 AccessToken 만료 → RefreshToken으로 재발급 시도
                handleRefresh(request, response);
                return;

            } else {
                log.debug("❌ JWT 토큰이 없거나 형식이 잘못됨 - uri: {}", requestURI);
            }

        } catch (Exception e) {
            log.error("❗ JWT 필터 처리 중 예외 - uri: {}, message: {}", requestURI, e.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    private void handleRefresh(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String refreshToken = getRefreshTokenFromCookies(request);

        if (refreshToken != null && jwtTokenProvider.validateToken(refreshToken)) {
            String username = jwtTokenProvider.getUsernameFromToken(refreshToken);
            String storedRefreshToken = redisTemplate.opsForValue().get("refresh:" + username);

            if (refreshToken.equals(storedRefreshToken)) {
                Authentication authentication = jwtTokenProvider.getAuthentication(refreshToken);
                SecurityContextHolder.getContext().setAuthentication(authentication);

                String newAccessToken = jwtTokenProvider.generateToken(authentication, false);
                String newRefreshToken = jwtTokenProvider.generateToken(authentication, true);

                redisTemplate.opsForValue().set("refresh:" + username, newRefreshToken,
                        jwtTokenProvider.getRefreshTokenExpiration(), TimeUnit.MILLISECONDS);

                // 🍪 새 RefreshToken 쿠키 설정
                Cookie newCookie = new Cookie("refreshToken", newRefreshToken);
                newCookie.setHttpOnly(true);
                newCookie.setSecure(true);
                newCookie.setPath("/");
                newCookie.setMaxAge((int) (jwtTokenProvider.getRefreshTokenExpiration() / 1000));
                response.addCookie(newCookie);

                // 🔐 새 AccessToken 응답 반환
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");
                response.setHeader("Authorization", "Bearer " + newAccessToken);
                response.getWriter().write("{\"accessToken\": \"" + newAccessToken + "\"}");
                response.getWriter().flush();

                log.info("♻️ AccessToken + RefreshToken 재발급 완료 - user: {}", username);
                return;

            } else {
                // ❌ Redis 저장된 토큰 불일치 (탈취 가능성)
                redisTemplate.delete("refresh:" + username);

                // 쿠키 제거
                Cookie expiredCookie = new Cookie("refreshToken", null);
                expiredCookie.setHttpOnly(true);
                expiredCookie.setSecure(true);
                expiredCookie.setPath("/");
                expiredCookie.setMaxAge(0);
                response.addCookie(expiredCookie);

                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Refresh Token이 유효하지 않습니다. 다시 로그인해주세요.");
                log.warn("❌ RefreshToken 불일치: {}", username);
            }

        } else {
            log.warn("❌ 유효하지 않은 RefreshToken 요청");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Refresh Token이 유효하지 않거나 만료되었습니다.");
        }
    }

    private String resolveToken(HttpServletRequest request) {
        String bearer = request.getHeader("Authorization");
        return (StringUtils.hasText(bearer) && bearer.startsWith("Bearer "))
                ? bearer.substring(7)
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
