# 사용할 Java 런타임 이미지 (여기서는 OpenJDK 17을 slim 버전으로 사용)
FROM openjdk:17-jdk-slim

# Docker 이미지 내부에 컨테이너가 사용할 작업 디렉토리를 설정
WORKDIR /app

# Gradle 또는 Maven 빌드 결과물의 경로를 설정 (프로젝트에 맞게 수정)
# Maven 사용 시: target/*.jar
# Gradle 사용 시: build/libs/*.jar
ARG JAR_FILE=build/libs/*.jar

# 로컬에서 빌드된 JAR 파일을 컨테이너의 /app 디렉토리로 복사
COPY ${JAR_FILE} app.jar

# Spring Boot 애플리케이션의 기본 포트 노출 (선택 사항, 문서화 목적)
EXPOSE 8080

# 컨테이너 시작 시 실행될 명령어
# java -jar 명령어로 Spring Boot 애플리케이션을 실행
ENTRYPOINT ["java", "-jar", "app.jar"]