package com.next_step_be.next_step_be.config;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.FileInputStream;
import java.io.IOException;

@Configuration
public class GcsConfig {

    @Value("${gcp.credentials.path}")
    private String gcpCredentialsPath;

    @Bean
    public Storage storage() throws IOException {
    	try (FileInputStream serviceAccountStream = new FileInputStream(gcpCredentialsPath)) {
            GoogleCredentials credentials = GoogleCredentials.fromStream(serviceAccountStream);
            return StorageOptions.newBuilder().setCredentials(credentials).build().getService();
        } catch (IOException e) {
            throw new RuntimeException("GCP 인증 파일을 로드하는 데 실패했습니다. 경로: " + gcpCredentialsPath, e);
        }
    }
}
