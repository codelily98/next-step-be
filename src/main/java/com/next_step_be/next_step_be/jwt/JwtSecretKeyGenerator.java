//package com.next_step_be.next_step_be.jwt;
//
//import java.util.Base64;
//import javax.crypto.KeyGenerator;
//import javax.crypto.SecretKey;
//import java.security.NoSuchAlgorithmException;
//
//public class JwtSecretKeyGenerator {
//    public static void main(String[] args) throws NoSuchAlgorithmException {
//        // HMAC-SHA256 알고리즘에 적합한 키 길이를 설정 (예: 256비트 = 32바이트)
//        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
//        keyGen.init(256); // 256비트 키 생성
//        SecretKey secretKey = keyGen.generateKey();
//
//        // 생성된 비밀 키를 Base64로 인코딩하여 출력
//        String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
//        System.out.println("Generated Base64 Encoded Secret Key: " + encodedKey);
//    }
//}