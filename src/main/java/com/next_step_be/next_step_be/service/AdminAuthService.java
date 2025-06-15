package com.next_step_be.next_step_be.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AdminAuthService {

    private final RedisTemplate<String, String> redisTemplate;

    public boolean forceLogout(String username) {
        String refreshKey = "refresh:" + username;
        String userCacheKey = "user:" + username;

        boolean existed = false;

        if (Boolean.TRUE.equals(redisTemplate.hasKey(refreshKey))) {
            redisTemplate.delete(refreshKey);
            existed = true;
        }

        if (Boolean.TRUE.equals(redisTemplate.hasKey(userCacheKey))) {
            redisTemplate.delete(userCacheKey);
            existed = true;
        }

        return existed;
    }
}
