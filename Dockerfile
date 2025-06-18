# 1. Java 17 slim 이미지 사용
FROM openjdk:17-jdk-slim

# 2. 작업 디렉토리 설정
WORKDIR /app

# 3. 서비스 계정 키 파일 복사 (호스트의 keys/gcs-key.json 경로를 기준으로 함)
COPY keys/gcs-key.json /app/gcp-key.json

# 4. 환경변수 설정 (GCS 인증용)
ENV GOOGLE_APPLICATION_CREDENTIALS=/app/gcp-key.json

# 5. JAR 파일 복사
COPY build/libs/*.jar app.jar

# 6. 포트 노출
EXPOSE 8080

# 7. 애플리케이션 실행
ENTRYPOINT ["java", "-jar", "app.jar"]
