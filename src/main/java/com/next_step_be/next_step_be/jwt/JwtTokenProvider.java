package com.next_step_be.next_step_be.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.io.Decoders; // Base64 디코딩을 위해 추가
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean; // 초기화 후 Bean을 사용하기 위해
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User; // Spring Security의 User 클래스
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Slf4j // Lombok 로깅
@Component // 스프링 빈으로 등록
public class JwtTokenProvider implements InitializingBean { // Secret Key 초기화를 위해 InitializingBean 구현

    private final String secret;
    private final long ACCESS_TOKEN_EXPIRE_TIME;
    private final long REFRESH_TOKEN_EXPIRE_TIME;

    private Key key; // JWT 서명에 사용할 키

    // application.yml에서 주입받을 값들
    public JwtTokenProvider(@Value("${jwt.secret}") String secret,
                            @Value("${jwt.expiration}") long accessTokenExpireTime,
                            @Value("${jwt.refresh_expiration}") long refreshTokenExpireTime) {
        this.secret = secret;
        this.ACCESS_TOKEN_EXPIRE_TIME = accessTokenExpireTime;
        this.REFRESH_TOKEN_EXPIRE_TIME = refreshTokenExpireTime;
    }

    // 빈이 초기화된 후 secret 값을 Key로 변환
    @Override
    public void afterPropertiesSet() throws Exception {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    // Access Token 또는 Refresh Token 생성
    public String generateToken(Authentication authentication, boolean isRefreshToken) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + (isRefreshToken ? REFRESH_TOKEN_EXPIRE_TIME : ACCESS_TOKEN_EXPIRE_TIME));

        return Jwts.builder()
                .setSubject(authentication.getName()) // 사용자 이름(Principal)
                .claim("auth", authorities) // 권한 정보
                .setIssuedAt(now) // 토큰 발행 시간
                .setExpiration(expiryDate) // 토큰 만료 시간
                .signWith(key, SignatureAlgorithm.HS256) // 서명 알고리즘과 키
                .compact();
    }

    // JWT 토큰에서 인증 정보 조회
    public Authentication getAuthentication(String token) {
        Claims claims = parseClaims(token); // 토큰에서 클레임(정보) 추출

        // 권한 정보 파싱
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("auth").toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        // Spring Security의 User 객체 생성 (Principal)
        User principal = new User(claims.getSubject(), "", authorities);

        // UsernamePasswordAuthenticationToken 반환
        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }
    
    // 토큰에서 사용자 이름 추출
    public String getUsernameFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    // 토큰 유효성 검사
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("잘못된 JWT 서명입니다.", e);
        } catch (ExpiredJwtException e) {
            log.info("만료된 JWT 토큰입니다.", e);
        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 JWT 토큰입니다.", e);
        } catch (IllegalArgumentException e) {
            log.info("JWT 토큰이 잘못되었습니다.", e);
        }
        return false;
    }

    // 토큰에서 Claims 추출 (만료된 토큰에서도 정보 추출 가능)
    private Claims parseClaims(String accessToken) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims(); // 만료된 토큰의 경우에도 클레임을 반환
        }
    }
    
    // Refresh Token 만료 시간 getter (Redis 저장을 위해)
    public long getRefreshTokenExpiration() {
        return REFRESH_TOKEN_EXPIRE_TIME;
    }

    // Access Token의 남은 유효 시간을 가져오는 메서드 추가
    public Long getExpiration(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            Date expiration = claims.getExpiration();
            long now = new Date().getTime();
            return expiration.getTime() - now; // 남은 시간 (밀리초)
        } catch (Exception e) {
            return null; // 토큰 파싱 실패 시 null 반환
        }
    }
}