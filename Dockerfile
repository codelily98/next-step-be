# 1. 사용할 Java 런타임 이미지
FROM openjdk:17-jdk-slim

# 2. 작업 디렉토리 설정
WORKDIR /app

# 3. JAR 복사
ARG JAR_FILE=build/libs/*.jar
COPY ${JAR_FILE} app.jar

# 4. 포트 노출
EXPOSE 8080

# 5. 실행
ENTRYPOINT ["java", "-jar", "app.jar"]
