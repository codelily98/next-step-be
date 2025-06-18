package com.next_step_be.next_step_be.repository;

import com.next_step_be.next_step_be.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository // 스프링 빈으로 등록
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username); // 사용자 이름으로 User 객체 조회
    boolean existsByUsername(String username); // 사용자 이름 존재 여부 확인
    boolean existsByNickname(String nickname); // ✅ 추가
}