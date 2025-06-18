package com.next_step_be.next_step_be.service;

import com.google.cloud.storage.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.util.UUID;

@Component
public class GcsUploader {

    private final Storage storage;
    private final String bucketName;
    private final String uploadPath;

    public GcsUploader(Storage storage,
                       @Value("${gcp.bucket}") String bucketName,
                       @Value("${gcp.upload-path}") String uploadPath) {
        this.storage = storage;
        this.bucketName = bucketName;
        this.uploadPath = uploadPath;
    }

    public String upload(MultipartFile file) {
        try {
            String filename = UUID.randomUUID() + "_" + file.getOriginalFilename();
            String objectName = uploadPath + filename;

            BlobInfo blobInfo = BlobInfo.newBuilder(bucketName, objectName)
                    .setContentType(file.getContentType())
                    .build();

            storage.create(blobInfo, file.getBytes());

            return String.format("https://storage.googleapis.com/%s/%s", bucketName, objectName);
        } catch (Exception e) {
            throw new RuntimeException("파일 업로드 실패", e);
        }
    }
}
