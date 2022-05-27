package com.goodbam.jwtServer.config.jwt;

public interface JwtProperties {
	String SECRET = "good"; // 서버만 알고 있는 개인키
	int EXPIRATION_TIME = 60000*10; // 60000 1분 (1/1000초)
	String TOKEN_PREFIX = "Bearer ";
	String HEADER_STRING = "Authorization";
}
