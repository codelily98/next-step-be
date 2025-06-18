package com.next_step_be.next_step_be.service;

import com.next_step_be.next_step_be.domain.User;
import com.next_step_be.next_step_be.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

@Service
@RequiredArgsConstructor
@Transactional
public class UserService {

    private final GcsUploader gcsUploader; // 오타 수정
    private final UserRepository userRepository;

    public boolean nicknameExists(String nickname) {
        return userRepository.existsByNickname(nickname);
    }

    public void updateProfile(String username, String nickname, MultipartFile imageFile) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));

        // 닉네임 변경 시 중복 검사
        if (!user.getNickname().equals(nickname) && userRepository.existsByNickname(nickname)) {
            throw new IllegalArgumentException("이미 사용 중인 닉네임입니다.");
        }

        // 기존 이미지 유지, 새 이미지가 있을 경우 업로드
        String imageUrl = user.getProfileImageUrl();
        if (imageFile != null && !imageFile.isEmpty()) {
            imageUrl = gcsUploader.upload(imageFile); // ✅ GCS 업로드로 대체
        }

        user.updateProfile(nickname, imageUrl); // ✅ User 엔티티 메서드 사용
    }

    public String getCurrentNickname(String username) {
        return userRepository.findByUsername(username)
                .map(User::getNickname)
                .orElse(null);
    }

    public String getCurrentProfileImageUrl(String username) {
        return userRepository.findByUsername(username)
                .map(User::getProfileImageUrl)
                .orElse(null);
    }
    
    public User getUserByUsername(String username) {
        return userRepository.findByUsername(username).orElse(null);
    }

}
