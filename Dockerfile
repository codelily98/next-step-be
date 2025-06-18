# 1. 사용할 Java 런타임 이미지
FROM openjdk:17-jdk-slim

# 2. 작업 디렉토리 설정
WORKDIR /app

# 3. JAR 파일 복사 (Gradle 기준)
ARG JAR_FILE=build/libs/*.jar
COPY ${JAR_FILE} app.jar

# 4. 서비스 계정 키 파일 복사 (빌드 시 함께 전달)
COPY gcp-service-key.json /app/gcp-service-key.json

# 5. 환경 변수 설정 (GCP 인증)
ENV GOOGLE_APPLICATION_CREDENTIALS=/app/gcp-service-key.json

# 6. 포트 노출 (문서 목적)
EXPOSE 8080

# 7. 실행 명령어
ENTRYPOINT ["java", "-jar", "app.jar"]
