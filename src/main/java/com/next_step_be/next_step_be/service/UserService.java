package com.next_step_be.next_step_be.service;

import com.next_step_be.next_step_be.domain.User;
import com.next_step_be.next_step_be.dto.UpdateProfileRequest;
import com.next_step_be.next_step_be.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

@Service
@RequiredArgsConstructor
@Transactional
public class UserService {

    private final GcsUploader gcsUploader; // GCS 업로더
    private final UserRepository userRepository;

    private static final long MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
    private static final String[] ALLOWED_FILE_TYPES = {
            "image/jpeg", "image/png", "image/webp", "image/gif"
    };

    public boolean nicknameExists(String nickname) {
        return userRepository.existsByNickname(nickname);
    }

    public void updateProfile(String username, String nickname, MultipartFile profileImage) {
        // 사용자 조회
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));

        // 닉네임 변경 시 중복 검사
        if (nickname != null && !nickname.trim().isEmpty()) {
            if (!nickname.equals(user.getNickname()) && userRepository.existsByNickname(nickname)) {
                throw new IllegalArgumentException("이미 사용 중인 닉네임입니다.");
            }
        } else {
            nickname = user.getNickname(); // 기존 닉네임 유지
        }

        // 프로필 이미지 처리
        String imageUrl = user.getProfileImageUrl();
        if (profileImage != null && !profileImage.isEmpty()) {
            // 파일 형식과 크기 검증
            if (!isValidFileType(profileImage.getContentType())) {
                throw new IllegalArgumentException("지원되지 않는 파일 형식입니다.");
            }

            if (profileImage.getSize() > MAX_FILE_SIZE) {
                throw new IllegalArgumentException("파일 크기는 50MB 이하로 업로드해야 합니다.");
            }

            // GCS 업로드
            imageUrl = gcsUploader.upload(profileImage);
        }

        // 사용자 프로필 업데이트
        user.updateProfile(nickname, imageUrl);
    }

    private boolean isValidFileType(String fileType) {
        for (String allowedType : ALLOWED_FILE_TYPES) {
            if (allowedType.equals(fileType)) {
                return true;
            }
        }
        return false;
    }

    public User getUserByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));
    }
}
