package com.next_step_be.next_step_be.config;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.FileInputStream;

@Configuration
public class GcsConfig {

    @Bean
    public Storage storage() throws Exception {
        String credentialsPath = "/app/keys/gcp-key.json";

        return StorageOptions.newBuilder()
                .setCredentials(GoogleCredentials.fromStream(new FileInputStream(credentialsPath)))
                .setProjectId("next-step-460309")
                .build()
                .getService();
    }
}
