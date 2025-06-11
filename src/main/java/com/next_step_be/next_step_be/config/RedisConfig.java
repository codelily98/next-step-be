package com.next_step_be.next_step_be.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;
// import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer; // 필요에 따라 추가

@Configuration
public class RedisConfig {

    @Value("${spring.data.redis.host}")
    private String redisHost;

    @Value("${spring.data.redis.port}")
    private int redisPort;
    
    // Redis 비밀번호 (없을 경우 빈 문자열) - 주석 처리 해제 시 application.yml에 비밀번호 설정 필요
	@Value("${spring.data.redis.password:}")
	private String redisPassword;

    @Bean
    public RedisConnectionFactory redisConnectionFactory() {
        LettuceConnectionFactory lettuceConnectionFactory = new LettuceConnectionFactory(redisHost, redisPort);
        // Redis 비밀번호가 설정되어 있다면 주석 해제하여 사용
        if (redisPassword != null && !redisPassword.isEmpty()) {
            lettuceConnectionFactory.setPassword(redisPassword);
        }
        return lettuceConnectionFactory;
    }

    // 이 메서드만 남겨두고, 아래의 중복되는 redisTemplate() 메서드는 제거합니다.
    // RedisTemplate을 생성하고 String 직렬화 설정을 합니다.
    @Bean
    public RedisTemplate<String, String> redisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, String> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        // Key Serializer: String (예: 사용자 이름)
        template.setKeySerializer(new StringRedisSerializer());

        // Value Serializer: String (예: Refresh Token)
        // 만약 Redis에 JSON 형식의 객체를 저장해야 한다면 Jackson2JsonRedisSerializer 등을 사용해야 합니다.
        template.setValueSerializer(new StringRedisSerializer());

        // Hash Key Serializer: String
        template.setHashKeySerializer(new StringRedisSerializer());

        // Hash Value Serializer: String
        template.setHashValueSerializer(new StringRedisSerializer());

        return template;
    }

    // 이전에 중복되었던 public RedisTemplate<String, String> redisTemplate() {} 메서드는 삭제했습니다.
    // Spring Boot는 RedisTemplate을 위한 ConnectionFactory를 자동으로 주입해주므로,
    // 이 방식이 더 표준적이고 권장됩니다.
}